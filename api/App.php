<?php
if(class_exists('Extension_PageMenuItem')):
class WgmGoogle_SetupMenuItem extends Extension_PageMenuItem {
	const POINT = 'wgm.google.setup.menu';
	
	function render() {
		$tpl = DevblocksPlatform::services()->template();
		$tpl->assign('extension', $this);
		$tpl->display('devblocks:wgm.google::setup/menu_item.tpl');
	}
};
endif;

if(class_exists('Extension_PageSection')):
class WgmGoogle_SetupSection extends Extension_PageSection {
	const ID = 'wgm.google.setup.page';
	
	function render() {
		$tpl = DevblocksPlatform::services()->template();
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
	
	function renderConfigForm(Model_ConnectedAccount $account) {
		$tpl = DevblocksPlatform::services()->template();
		$active_worker = CerberusApplication::getActiveWorker();
		
		$tpl->assign('account', $account);
		
		$params = $account->decryptParams($active_worker);
		$tpl->assign('params', $params);
		
		$tpl->display('devblocks:wgm.google::provider/google.tpl');
	}
	
	function saveConfigForm(Model_ConnectedAccount $account, array &$params) {
		@$edit_params = DevblocksPlatform::importGPC($_POST['params'], 'array', array());
		
		$active_worker = CerberusApplication::getActiveWorker();
		$encrypt = DevblocksPlatform::services()->encryption();
		
		// Decrypt OAuth params
		if(isset($edit_params['params_json'])) {
			if(false == ($outh_params_json = $encrypt->decrypt($edit_params['params_json'])))
				return "The connected account authentication is invalid.";
				
			if(false == ($oauth_params = json_decode($outh_params_json, true)))
				return "The connected account authentication is malformed.";
			
			if(is_array($oauth_params))
			foreach($oauth_params as $k => $v)
				$params[$k] = $v;
		}
		
		return true;
	}
	
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
	
	function oauthRender() {
		@$form_id = DevblocksPlatform::importGPC($_REQUEST['form_id'], 'string', '');
		
		// Store the $form_id in the session
		$_SESSION['oauth_form_id'] = $form_id;
		
		$url_writer = DevblocksPlatform::services()->url();
		
		// [TODO] Report about missing app keys
		if(false == ($app_keys = $this->_getAppKeys()))
			return false;
		
		$oauth = DevblocksPlatform::services()->oauth($app_keys['key'], $app_keys['secret']);
		
		// Persist the view_id in the session
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
		@$oauth_state = $_SESSION['oauth_state'];
		
		@$code = DevblocksPlatform::importGPC($_REQUEST['code'], 'string', '');
		@$state = DevblocksPlatform::importGPC($_REQUEST['state'], 'string', '');
		@$error = DevblocksPlatform::importGPC($_REQUEST['error'], 'string', '');
		
		$form_id = $_SESSION['oauth_form_id'];
		unset($_SESSION['oauth_form_id']);
		
		$active_worker = CerberusApplication::getActiveWorker();
		$url_writer = DevblocksPlatform::services()->url();
		$encrypt = DevblocksPlatform::services()->encryption();
		
		$redirect_url = $url_writer->write(sprintf('c=oauth&a=callback&ext=%s', ServiceProvider_Google::ID), true);
		
		if(false == ($app_keys = $this->_getAppKeys()))
			return false;
		
		if(!empty($error))
			return false;
		
		$access_token_url = 'https://www.googleapis.com/oauth2/v4/token';
		
		$oauth = DevblocksPlatform::services()->oauth($app_keys['key'], $app_keys['secret']);
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
		
		// Load their profile
		
		$json = $oauth->executeRequestWithToken('GET', 'https://www.googleapis.com/plus/v1/people/me', 'Bearer');
		
		// Die with error
		if(!is_array($json))
			return false;
		
		$params['label'] = $json['displayName'];
		
		// Output
		$tpl = DevblocksPlatform::services()->template();
		$tpl->assign('form_id', $form_id);
		$tpl->assign('label', $params['label']);
		$tpl->assign('params_json', $encrypt->encrypt(json_encode($params)));
		$tpl->display('devblocks:cerberusweb.core::internal/connected_account/oauth_callback.tpl');
	}
	
	function authenticateHttpRequest(Model_ConnectedAccount $account, &$ch, &$verb, &$url, &$body, &$headers) {
		$credentials = $account->decryptParams();
		
		if(
			!isset($credentials['access_token'])
		)
			return false;
		
		if(false == ($app_keys = $this->_getAppKeys()))
			return false;
		
		$oauth = DevblocksPlatform::services()->oauth($app_keys['key'], $app_keys['secret']);
		$oauth->setTokens($credentials['access_token']);
		$result = $oauth->authenticateHttpRequest($ch, $verb, $url, $body, $headers);
		return $result;
	}
}