<?php
	namespace App\Firewall\Core;

	class Template_Juniper_Junos_Set extends Template_Juniper_Junos
	{
		const PLATFORM = 'juniper';
		const TEMPLATE = 'junos_set';

		const UPDATE_MODE_MERGE = 'merge';
		const UPDATE_MODE_REPLACE = 'replace';

		const UPDATE_MODES = array(
				self::UPDATE_MODE_MERGE,
				self::UPDATE_MODE_REPLACE
		);


		/**
		  * @return array Variables for rendering template
		  */
		protected function _getTemplateVars()
		{
			$vars = parent::_getTemplateVars();
			$vars['zones'] = array_keys($this->_siteApi->zones);

			$vars['UPDATE_MODE_MERGE'] = self::UPDATE_MODE_MERGE;
			$vars['UPDATE_MODE_REPLACE'] = self::UPDATE_MODE_REPLACE;

			if(isset($this->_firewall->config->templates->{self::PLATFORM.'-'.self::TEMPLATE}->updateMode))
			{
				$updateMode = $this->_firewall->config->templates->{self::PLATFORM.'-'.self::TEMPLATE}->updateMode;

				if(in_array($updateMode, self::UPDATE_MODES, true)) {
					$vars['updateMode'] = $updateMode;
				}
				else {
					throw new Exception("Configuration 'updateMode' for FIREWALL template '".self::PLATFORM."-".self::TEMPLATE."' is not valid", E_USER_ERROR);
				}
			}
			else {
				throw new Exception("Unable to retrieve 'updateMode' configuration for FIREWALL template '".self::PLATFORM."-".self::TEMPLATE."'", E_USER_ERROR);
			}

			return $vars;
		}
	}