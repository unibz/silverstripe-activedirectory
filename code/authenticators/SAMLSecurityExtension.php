<?php

class SAMLSecurityExtension extends Extension {

	/**
	 * Will redirect the user directly to the ADFS if:
	 * 1) the 'SAMLAuthenticator' is the default authenticator
	 * 2) there isn't a GET param showloginform set to 1
	 * 3) the member is currently logged in
	 * 4) the URL contains Security/login
	 * 5) there are messages form messages
	 * 
	 * @return void
	 */
	public function onBeforeSecurityLogin() {

		if(Authenticator::get_default_authenticator() != 'SAMLAuthenticator') {
			return;
		}

		// force the login of the loginform
		if(isset($_GET['showloginform']) && $_GET['showloginform'] == 1) {
			return;
		}

		// if member is already logged in, don't auto-sign-on
		$member = Member::currentUser();
		if($member && $member->exists()) {
			return;
		}

		if(!empty($_REQUEST['url']) && stristr($_REQUEST['url'], 'Security/login')) {
			return;
		}
		// if there are form messages, don't auto-sign-on
		if(Session::get('FormInfo')) {
			// since FormInfo can be a "nulled" array, we have to check
			foreach(Session::get('FormInfo') as $form => $info) {
				foreach($info as $name => $value) {
					if($value !== null) {
						return;
					}
				}
			}
		}

		$backURL = Session::get('BackURL');
		if(isset($_REQUEST['BackURL'])) {
			$backURL = $_REQUEST['BackURL'];
		}

		$authenticator = Injector::inst()->create('SAMLAuthenticator');
		$authenticator->authenticate(array("BackURL" => $backURL));
	}
}
