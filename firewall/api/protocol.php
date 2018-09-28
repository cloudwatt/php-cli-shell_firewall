<?php
	class Firewall_Api_Protocol extends Firewall_Api_Abstract
	{
		const OBJECT_TYPE = 'protocol';
		const OBJECT_NAME = 'protocol';
		const FIELD_NAME = 'name';

		const PROTO_SEPARATOR = '/';

		protected $_datas = array(
			'name' => null,
			'protocol' => null,
		);


		public function __construct($name = null, $protocol = null)
		{
			$this->name($name);
			$this->protocol($protocol);
		}

		public function protocol($protocol)
		{
			if(preg_match('#^(((tcp|udp)/[0-9]{1,5}(-[0-9]{1,5})?)|(icmp/[0-9]{1,2}(:[0-9]{1,2})?)|([a-z]+))$#i', $protocol))
			{
				$status = true;
				$separator = self::PROTO_SEPARATOR;
				$parts = explode($separator, $protocol, 2);
				$protocol = mb_strtolower($parts[0]);

				switch($protocol)
				{
					case 'tcp':
					case 'udp':
					{
						if(isset($parts[1]))
						{
							$ports = explode('-', $parts[1], 2);

							foreach($ports as $port)
							{
								if(Tools::is('int&&<=0', $port) || $port > 65535) {
									$status = false;
									break(2);
								}
							}

							if(isset($ports[1]) && $ports[0] >= $ports[1]) {
								$status = false;
							}
							else {
								$protocol .= $separator.$parts[1];
							}
						}
						else {
							$status = false;
						}
						break;
					}
					case 'icmp':
					{
						if(isset($parts[1]))
						{
							$typeCode = explode(':', $parts, 2);

							foreach($typeCode as $item)
							{
								if(!Tools::is('int&&>0', $item) || $item > 99) {
									$status = false;
									break(2);
								}
							}

							$protocol .= $separator.$parts[1];
						}
						else {
							$status = false;
						}
						break;
					}
					case 'ip':
					case 'esp':
					case 'gre': {
						break;
					}
					default: {
						$status = false;
					}
				}

				if($status) {
					$this->_datas['protocol'] = $protocol;
					return true;
				}
			}

			return false;
		}

		public function isValid($returnInvalidAttributes = false)
		{
			return ($this->_datas['name'] !== null && $this->_datas['protocol'] !== null);
		}
	}