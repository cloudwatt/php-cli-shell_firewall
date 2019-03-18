<?php
	namespace App\Firewall;

	class Shell_Program_Firewall_Object extends Shell_Program_Firewall_Abstract
	{
		const OBJECT_IDS = array(
			Core\Api_Site::OBJECT_TYPE,
			Core\Api_Host::OBJECT_TYPE,
			Core\Api_Subnet::OBJECT_TYPE,
			Core\Api_Network::OBJECT_TYPE,
			Core\Api_Rule::OBJECT_TYPE,
		);

		const OBJECT_KEYS = array(
			Core\Api_Site::OBJECT_TYPE => Core\Api_Site::OBJECT_KEY,
			Core\Api_Host::OBJECT_TYPE => Core\Api_Host::OBJECT_KEY,
			Core\Api_Subnet::OBJECT_TYPE => Core\Api_Subnet::OBJECT_KEY,
			Core\Api_Network::OBJECT_TYPE => Core\Api_Network::OBJECT_KEY,
			Core\Api_Rule::OBJECT_TYPE => Core\Api_Rule::OBJECT_KEY,
		);

		const OBJECT_CLASSES = array(
			Core\Api_Site::OBJECT_TYPE => 'App\Firewall\Core\Api_Site',
			Core\Api_Host::OBJECT_TYPE => 'App\Firewall\Core\Api_Host',
			Core\Api_Subnet::OBJECT_TYPE => 'App\Firewall\Core\Api_Subnet',
			Core\Api_Network::OBJECT_TYPE => 'App\Firewall\Core\Api_Network',
			Core\Api_Rule::OBJECT_TYPE => 'App\Firewall\Core\Api_Rule',
		);
	}