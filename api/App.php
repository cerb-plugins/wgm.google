<?php
if(class_exists('Extension_PageMenuItem')):
class WgmGoogle_SetupMenuItem extends Extension_PageMenuItem {
	const POINT = 'wgm.google.setup.menu';
	
	function render() {
		$tpl = DevblocksPlatform::getTemplateService();
		$tpl->assign('extension', $this);
		$tpl->display('devblocks:wgm.google::setup/menu_item.tpl');
	}
};
endif;

if(class_exists('Extension_PageSection')):
class WgmGoogle_SetupSection extends Extension_PageSection {
	const ID = 'wgm.google.setup.page';
	
	function render() {
		$tpl = DevblocksPlatform::getTemplateService();
		$visit = CerberusApplication::getVisit();
		
		$visit->set(ChConfigurationPage::ID, 'google');
		
		$credentials = DevblocksPlatform::getPluginSetting('wgm.google', 'credentials', false, true, true);
		$tpl->assign('credentials', $credentials);

		$tpl->display('devblocks:wgm.google::setup/index.tpl');
	}
	
	function saveJsonAction() {
		try {
			@$consumer_key = DevblocksPlatform::importGPC($_REQUEST['consumer_key'],'string','');
			@$consumer_secret = DevblocksPlatform::importGPC($_REQUEST['consumer_secret'],'string','');
			
			if(empty($consumer_key) || empty($consumer_secret))
				throw new Exception("Both the 'Client ID' and 'Client Secret' are required.");
			
			$credentials = [
				'consumer_key' => $consumer_key,
				'consumer_secret' => $consumer_secret,
			];
			
			DevblocksPlatform::setPluginSetting('wgm.google', 'credentials', $credentials, true, true);
			
			echo json_encode(array('status'=>true, 'message'=>'Saved!'));
			return;
			
		} catch (Exception $e) {
			echo json_encode(array('status'=>false, 'error'=>$e->getMessage()));
			return;
		}
	}
};
endif;

class ServiceProvider_Google extends Extension_ServiceProvider implements IServiceProvider_OAuth, IServiceProvider_HttpRequestSigner {
	const ID = 'wgm.google.service.provider';

	private function _getAppKeys() {
		if(false == ($credentials = DevblocksPlatform::getPluginSetting('wgm.google', 'credentials', false, true, true)))
			return;
		
		@$consumer_key = $credentials['consumer_key'];
		@$consumer_secret = $credentials['consumer_secret'];
		
		if(empty($consumer_key) || empty($consumer_secret))
			return false;
		
		return array(
			'key' => $consumer_key,
			'secret' => $consumer_secret,
		);
	}
	
	function renderPopup() {
		@$view_id = DevblocksPlatform::importGPC($_REQUEST['view_id'], 'string', '');
		
		$url_writer = DevblocksPlatform::getUrlService();
		
		// [TODO] Report about missing app keys
		if(false == ($app_keys = $this->_getAppKeys()))
			return false;
		
		$oauth = DevblocksPlatform::getOAuthService($app_keys['key'], $app_keys['secret']);
		
		// Persist the view_id in the session
		$_SESSION['oauth_view_id'] = $view_id;
		$_SESSION['oauth_state'] = CerberusApplication::generatePassword(24);
		
		// [TODO] This is basically just a Google Calendars provider
		
		// OAuth callback
		$redirect_url = $url_writer->write(sprintf('c=oauth&a=callback&ext=%s', ServiceProvider_Google::ID), true);

		$url = sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&prompt=%s",
			'https://accounts.google.com/o/oauth2/v2/auth',
			rawurlencode($app_keys['key']),
			rawurlencode($redirect_url),
			rawurlencode('https://www.googleapis.com/auth/calendar https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/plus.login https://www.googleapis.com/auth/plus.me https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile'),
			rawurlencode($_SESSION['oauth_state']),
			rawurlencode('consent select_account')
		);
		
		header('Location: ' . $url);
	}
	
	function oauthCallback() {
		@$view_id = $_SESSION['oauth_view_id'];
		@$oauth_state = $_SESSION['oauth_state'];
		
		@$code = DevblocksPlatform::importGPC($_REQUEST['code'], 'string', '');
		@$state = DevblocksPlatform::importGPC($_REQUEST['state'], 'string', '');
		@$error = DevblocksPlatform::importGPC($_REQUEST['error'], 'string', '');
		
		$active_worker = CerberusApplication::getActiveWorker();
		$url_writer = DevblocksPlatform::getUrlService();
		
		$redirect_url = $url_writer->write(sprintf('c=oauth&a=callback&ext=%s', ServiceProvider_Google::ID), true);
		
		if(false == ($app_keys = $this->_getAppKeys()))
			return false;
		
		if(!empty($error))
			return false;
		
		$access_token_url = 'https://www.googleapis.com/oauth2/v4/token';
		
		$oauth = DevblocksPlatform::getOAuthService($app_keys['key'], $app_keys['secret']);
		$oauth->setTokens($code);
		
		$params = $oauth->getAccessToken($access_token_url, array(
			'grant_type' => 'authorization_code',
			'code' => $code,
			'redirect_uri' => $redirect_url,
			'client_id' => $app_keys['key'],
			'client_secret' => $app_keys['secret'],
		));
		
		if(!is_array($params) || !isset($params['access_token'])) {
			return false;
		}
		
		$oauth->setTokens($params['access_token']);
		
		$label = 'Google';
		
		// Load their profile
		
		$json = $oauth->executeRequestWithToken('GET', 'https://www.googleapis.com/plus/v1/people/me', 'Bearer');
		
		// Die with error
		if(!is_array($json))
			return false;
		
		if(isset($json['displayName']))
			$label .= sprintf(": %s", $json['displayName']);
		
		// Save the account
		
		$id = DAO_ConnectedAccount::create(array(
			DAO_ConnectedAccount::NAME => $label,
			DAO_ConnectedAccount::EXTENSION_ID => ServiceProvider_Google::ID,
			DAO_ConnectedAccount::OWNER_CONTEXT => CerberusContexts::CONTEXT_WORKER,
			DAO_ConnectedAccount::OWNER_CONTEXT_ID => $active_worker->id,
		));
		
		DAO_ConnectedAccount::setAndEncryptParams($id, $params);
		
		if($view_id) {
			echo sprintf("<script>window.opener.genericAjaxGet('view%s', 'c=internal&a=viewRefresh&id=%s');</script>",
				rawurlencode($view_id),
				rawurlencode($view_id)
			);
			
			C4_AbstractView::setMarqueeContextCreated($view_id, CerberusContexts::CONTEXT_CONNECTED_ACCOUNT, $id);
		}
		
		echo "<script>window.close();</script>";
	}
	
	function authenticateHttpRequest(Model_ConnectedAccount $account, &$ch, &$verb, &$url, &$body, &$headers) {
		$credentials = $account->decryptParams();
		
		if(
			!isset($credentials['access_token'])
		)
			return false;
		
		if(false == ($app_keys = $this->_getAppKeys()))
			return false;
		
		$oauth = DevblocksPlatform::getOAuthService($app_keys['key'], $app_keys['secret']);
		$oauth->setTokens($credentials['access_token']);
		$result = $oauth->authenticateHttpRequest($ch, $verb, $url, $body, $headers);
		return $result;
	}
}