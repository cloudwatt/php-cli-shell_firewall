<?php
	namespace App\Firewall\Core;

	use Core as C;

	class Api_Protocol extends Api_Abstract implements Api_Interface
	{
		const OBJECT_KEY = 'Firewall_Api_Protocol';
		const OBJECT_TYPE = 'protocol';
		const OBJECT_NAME = 'protocol';

		const FIELD_NAME = 'name';

		const PROTO_SEPARATOR = '/';
		const PROTO_RANGE_SEPARATOR = '-';
		const PROTO_OPTIONS_SEPARATOR = ':';

		const PROTO_REGEX_VALIDATOR = '^((?:(?:tcp|udp)/[0-9]{1,5}(?:-[0-9]{1,5})?)|(?:icmp(?:4|6)?/[0-9]{1,3}(?::[0-9]{1,3})?)|(?:[a-z]+6?))$';

		const PROTOCOLS = array(
				'tcp', 'udp', 'icmp', 'icmp4', 'icmp6', 'gre', 'esp', 'ip'
		);

		/**
		  * @var array
		  */
		protected $_datas = array(
			'name' => null,
			'protocol' => null,
		);


		public function __construct($name = null, $protocol = null)
		{
			$this->name($name);
			$this->protocol($protocol);
		}

		/**
		  * Sets protocol name and options
		  *
		  * @param $protocol string Protocol name with or not protocol options
		  * @param $options string Protocol options
		  * @return bool
		  */
		public function protocol($protocol, $options = null)
		{
			if(preg_match('#'.self::PROTO_REGEX_VALIDATOR.'#i', $protocol))
			{
				$status = true;
				$separator = self::PROTO_SEPARATOR;
				$parts = explode($separator, $protocol, 2);
				$protocol = mb_strtolower($parts[0]);

				if(count($parts) === 2) {
					$options = $parts[1];
				}

				return $this->_protocol($protocol, $options);
			}

			return false;
		}

		/**
		  * Sets protocol options
		  *
		  * @param $options string Protocol options
		  * @return bool
		  */
		public function options($options)
		{
			$separator = self::PROTO_SEPARATOR;
			$protocol = $this->_datas['protocol'];
			$parts = explode($separator, $protocol, 2);
			return $this->_protocol($parts[0], $options);
		}

		/**
		  * Sets protocol name and options
		  *
		  * @param $protocol string
		  * @param $options string
		  * @return bool
		  */
		protected function _protocol($protocol, $options = null)
		{
			if(in_array($protocol, self::PROTOCOLS, true)) {
				$this->_datas['protocol'] = $protocol;
			}
			else {
				return false;
			}

			if($options === null) {
				return true;
			}
			else
			{
				switch($protocol)
				{
					case 'tcp':
					case 'udp':
					{
						if($this->_isValidTcpUdpPorts($options)) {
							$this->_datas['protocol'] .= self::PROTO_SEPARATOR.$options;
							return true;
						}
						break;
					}
					case 'icmp':
					case 'icmp4':
					case 'icmp6':
					{
						$icmpVersion = (substr($protocol, -1, 1) === '6') ? (6) : (4);

						if($this->_isValidIcmpOptions($icmpVersion, $options)) {
							$this->_datas['protocol'] .= self::PROTO_SEPARATOR.$options;
							return true;
						}
						break;
					}
				}
			}

			return false;
		}

		protected function _isValidTcpUdpPorts($ports)
		{
			$ports = explode(self::PROTO_RANGE_SEPARATOR, $ports, 2);

			foreach($ports as $port)
			{
				if(C\Tools::is('int&&<=0', $port) || $port > 65535) {
					return false;
				}
			}

			return (!isset($ports[1]) || $ports[0] < $ports[1]);
		}

		protected function _isValidIcmpOptions($icmpVersion, $options)
		{
			if($options !== null)
			{
				switch($icmpVersion)
				{
					case 4: {
						$lastType = 255;
						$lastCode = 254;
						break;
					}
					case 6: {
						$lastType = 255;
						$lastCode = 161;
						break;
					}
					default: {
						return false;
					}
				}

				$typeCode = explode(self::PROTO_OPTIONS_SEPARATOR, $options, 2);

				return (
					C\Tools::is('int&&>=0', $typeCode[0]) && $typeCode[0] <= $lastType &&
					(!isset($typeCode[1]) || (!C\Tools::is('int&&>=0', $typeCode[1]) && $typeCode[1] <= $lastCode))
				);
			}
			else {
				return true;
			}
		}

		public function isValid($returnInvalidAttributes = false)
		{		
			$tests = array(
				'string&&!empty' => array(
					self::FIELD_NAME,
					'protocol'
				)
			);

			return $this->_isValid($tests, $returnInvalidAttributes);
		}

		/**
		  * Gets protocol name only
		  *
		  * @return null|string
		  */
		public function getProtocolName()
		{
			$parts = explode(self::PROTO_OPTIONS_SEPARATOR, $this->_datas['protocol'], 2);
			return $parts[0];
		}

		/**
		  * Gets protocol options only
		  *
		  * @return null|string
		  */
		public function getProtocolOptions()
		{
			$parts = explode(self::PROTO_OPTIONS_SEPARATOR, $this->_datas['protocol'], 2);
			return (count($parts) === 2) ? ($parts[1]) : (null);
		}

		/**
		  * @param $name string
		  * @return mixed
		  */
		public function __get($name)
		{
			switch($name)
			{
				case 'proto':
				case 'protocolName': {
					return $this->getProtocolName();
				}
				case 'options':
				case 'protocolOptions': {
					return $this->getProtocolOptions();
				}
				default: {
					return parent::__get($name);
				}
			}
		}

		/**
		  * @var $datas array
		  * @return bool
		  */
		public function wakeup(array $datas)
		{
			$this->name($datas['name']);
			$this->protocol($datas['protocol']);
			return true;
		}
	}