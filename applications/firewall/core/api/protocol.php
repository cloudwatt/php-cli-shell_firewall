<?php
	namespace App\Firewall\Core;

	use Core as C;

	class Api_Protocol extends Api_Abstract implements Api_Interface
	{
		const OBJECT_KEY = 'Firewall_Api_Protocol';
		const OBJECT_TYPE = 'protocol';
		const OBJECT_NAME = 'protocol';

		const FIELD_NAME = 'name';
		const FIELD_ATTRS = array(
			'protocol'
		);

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
			'_id_' => null,
			'name' => null,
			'protocol' => null,
		);


		/**
		  * @param string $id ID
		  * @param string $name Name
		  * @param string $protocol Protocol
		  * @return $this
		  */
		public function __construct($id = null, $name = null, $protocol = null)
		{
			$this->id($id);
			$this->name($name);
			$this->protocol($protocol);
		}

		/**
		  * Sets protocol name and options
		  *
		  * @param string $protocol Protocol name with or not protocol options
		  * @param string $options Protocol options
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
		  * @param string $options Protocol options
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
		  * @param string $protocol
		  * @param string $options
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
				if(!(C\Tools::is('int&&>0', $port) && $port < 65535)) {
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
				array(self::FIELD_NAME => 'string&&!empty'),
				array('protocol' => 'string&&!empty'),
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

		public function includes(Api_Protocol $protocolApi)
		{
			return $this->_includes($protocolApi, false);
		}

		public function overlap(Api_Protocol $protocolApi)
		{
			return $this->_includes($protocolApi, true);
		}

		protected function _includes(Api_Protocol $protocolApi, $overlap = false)
		{
			$selfProtoName = $this->protocolName;
			$otherProtoName = $protocolApi->protocolName;

			if($selfProtoName === 'ip' || $otherProtoName === 'ip') {
				return true;
			}
			elseif($selfProtoName === $otherProtoName)
			{
				$selfProtoOptions = $this->protocolOptions;
				$otherProtoOptions = $protocolApi->protocolOptions;

				if($selfProtoOptions === $otherProtoOptions) {
					return true;
				}
				else
				{
					$selfProtoOptions = explode(self::PROTO_RANGE_SEPARATOR, $selfProtoOptions, 2);
					$otherProtoOptions = explode(self::PROTO_RANGE_SEPARATOR, $otherProtoOptions, 2);

					$selfProtoOptions = array_pad($selfProtoOptions, 2, $selfProtoOptions[0]);
					$otherProtoOptions = array_pad($otherProtoOptions, 2, $otherProtoOptions[0]);

					if(!$overlap) {
						return ($selfProtoOptions[0] <= $otherProtoOptions[0] && $selfProtoOptions[1] >= $otherProtoOptions[1]);
					}
					else
					{
						return (
							($selfProtoOptions[0] <= $otherProtoOptions[0] && $selfProtoOptions[1] >= $otherProtoOptions[1]) ||
							($selfProtoOptions[0] >= $otherProtoOptions[0] && $selfProtoOptions[1] <= $otherProtoOptions[1]) ||
							($selfProtoOptions[0] <= $otherProtoOptions[0] && $selfProtoOptions[1] <= $otherProtoOptions[1] && $selfProtoOptions[1] >= $otherProtoOptions[0]) ||
							($selfProtoOptions[0] >= $otherProtoOptions[0] && $selfProtoOptions[1] >= $otherProtoOptions[1] && $selfProtoOptions[0] <= $otherProtoOptions[1])
						);
					}
				}
			}

			return false;
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
		  * @return array
		  */
		public function sleep()
		{
			$datas = parent::sleep();
			$datas['protocol'] = $this->protocol;

			return $datas;
		}

		/**
		  * @param $datas array
		  * @return bool
		  */
		public function wakeup(array $datas)
		{
			$parentStatus = parent::wakeup($datas);
			$protocolStatus = $this->protocol($datas['protocol']);

			return ($parentStatus && $protocolStatus);
		}
	}