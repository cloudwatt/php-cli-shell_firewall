<?php
	namespace App\Firewall\Core;

	use ArrayObject;

	use Addon\Ipam;

	class Template_Cisco_Asa_Dap extends Template_Cisco_Asa
	{
		const VENDOR = 'cisco';
		const PLATFORM = 'asa';
		const TEMPLATE = 'dap';

		const ALLOW_RULE_MULTIZONES = self::RULE_MULTIZONES_DST;

		const ADD_NAME_PREFIX = '';
		const APP_NAME_PREFIX = '';
		const ACL_NAME_PREFIX = 'DAP_';

		const ADDRESS_IPv_SEPARATOR = '-';
		const ADDRESS_ESCAPE_CHARACTERS = '---';

		const ADDRESS_SUBNET_IPv_SEPARATOR = '-network';

		const RULE_TAG_DAP_SEPARATOR = '@';

		/**
		  * DAP
		  * @var array
		  */
		protected $_dap = array();


		/**
		  * @return array Variables for rendering template
		  */
		protected function _getTemplateVars()
		{
			$vars = parent::_getTemplateVars();
			$vars['dap'] = $this->_dap;
			return $vars;
		}

		/**
		  * @param App\Firewall\Core\Api_Rule $ruleApi
		  * @param array $srcZones
		  * @param array $sources
		  * @param array $dstZones
		  * @param array $destinations
		  * @return array|ArrayObject Policy accesslist datas
		  */
		protected function _toPolicyAcl(Api_Rule $ruleApi, array $srcZones, array $sources, array $dstZones, array $destinations)
		{
			$result = parent::_toPolicyAcl($ruleApi, $srcZones, $sources, $dstZones, $destinations);

			$tagDapSeparator = preg_quote(self::RULE_TAG_DAP_SEPARATOR, '#');

			foreach($result['tags'] as $tag)
			{
				if(preg_match('#^acl:([[:print:]]+)$#i', $tag, $matches)) {
					$result['aclName'] = self::ACL_NAME_PREFIX;
					$result['aclName'] .= $matches[1];
				}

				if(preg_match('#^dap:([[:print:]]+)'.$tagDapSeparator.'([0-9]+)$#i', $tag, $matches))
				{
					$dapName = $matches[1];
					$dapPriority = $matches[2];

					if(!array_key_exists($dapName, $this->_dap))
					{
						$this->_dap[$dapName] = array(
							'name' => $dapName,
							'priority' => $dapPriority,
							'acl' => array($result['aclName']),
						);
					}
					elseif(!in_array($result['aclName'], $this->_dap[$dapName]['acl'], true)) {
						$this->_dap[$dapName]['acl'][] = $result['aclName'];
					}
				}
			}

			// /!\ $result is ArrayObject so a reference
			//$this->_accessLists[$result['name']] = $result;
			return $result;
		}
	}