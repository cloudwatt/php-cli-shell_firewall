<?php
	class Firewall_Api_Site extends Firewall_Api_Abstract
	{
		const OBJECT_TYPE = 'site';
		const OBJECT_NAME = 'site';
		const FIELD_NAME = 'name';
		const FIELD_ATTRS = array(
			'equipment'
		);

		protected $_Firewall_Site;

		protected $_datas = array(
			'name' => null,
			'equipment' => null,
			'zones' => array(),
			'topology' => array(),
		);


		public function __construct($name = null)
		{
			$this->name($name);
		}

		public function name($name)
		{
			if(Tools::is('string&&!empty', $name)) {
				$this->_datas['name'] = $name;
				return $this->_loadConfig($name);
			}

			return false;
		}

		protected function _loadConfig($name)
		{
			$CONFIG = CONFIG::getInstance();
			$Firewall_Sites = new Firewall_Sites($CONFIG);

			if(isset($Firewall_Sites->$name))
			{
				$this->_Firewall_Site = $Firewall_Sites->{$name};
				$site = $this->_Firewall_Site->toArray();

				$this->_datas['equipment'] = $site['hostname'];
				$this->_datas['zones'] = $site['zones'];
				$this->_datas['topology'] = $site['topology'];
				return true;
			}
			else {
				return false;
			}
		}

		public function isValid($returnInvalidAttributes = false)
		{
			// @todo faire comme Firewall_Api_Rule?
			return (
				$this->_datas['name'] !== null &&
				$this->_datas['equipment'] !== null &&
				count($this->_datas['zones']) > 0 &&
				count($this->_datas['topology']) > 0
			);
		}

		public function __get($name)
		{
			switch($name)
			{
				case 'config':
				case 'configuration':
				case 'Firewall_Site': {
					return $this->_Firewall_Site;
				}
				default: {
					return parent::__get($name);
				}
			}
		}

		public function sleep()
		{
			return array('name' => $this->_datas['name']);
		}

		public function wakeup(array $datas, ArrayObject $objects = null)
		{
			$this->_datas['name'] = $datas['name'];
			return $this->_loadConfig($datas['name']);
		}
	}