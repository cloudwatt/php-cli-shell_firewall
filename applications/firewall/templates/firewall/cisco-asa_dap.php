<?php
/**
  * /!\ La balise de fermeture de PHP '?>' supprime le saut de ligne qui la suit immédiatement
  * Un double saut de ligne est le workaround le plus simple à mettre en place
  */

	namespace App\Firewall;

	use App\Firewall\Core;
?>
<?php
	foreach($this->addressBook as $addresses)
	{
		// IPv4 & IPv6
		foreach($addresses as $address)
		{
			if(array_key_exists('__doNotCreateAdd__', $address) && $address['__doNotCreateAdd__']) {
				continue;
			}

			switch($address['type'])
			{
				case Core\Api_Host::OBJECT_TYPE: {
					$type = 'host';
					break;
				}
				case Core\Api_Subnet::OBJECT_TYPE: {
					$type = 'subnet';
					$address['address'] = implode(' ', $address['address']);
					break;
				}
				case Core\Api_Network::OBJECT_TYPE: {
					$type = 'range';
					$address['address'] = implode(' ', $address['address']);
					break;
				}
				default: {
					throw new Exception("Address type '".$address['type']."' is not valid", E_USER_ERROR);
				}
			}
?>

object network <?php echo $address['name']; ?>

<?php echo $type; ?> <?php echo $address['address']; ?>

exit
<?php
		}
	}
?>

<?php
	$aclNames = array();

	foreach($this->accessLists as $accessList)
	{
		if(!in_array($accessList['aclName'], $aclNames, true))
		{
			$aclNames[] = $accessList['aclName'];
?>

clear configure access-list ACL_NEW_<?php echo $accessList['aclName']; ?>
<?php
		}

		$action = ($accessList['action']) ? ('permit') : ('deny');

		foreach($accessList['srcAdds'] as $srcAdd)
		{
			foreach($accessList['dstAdds'] as $dstAdd)
			{
				if($srcAdd['IPv'] !== $dstAdd['IPv']) {
					continue;
				}

				foreach($accessList['protoApps'] as $protoApp)
				{
					$acl = array();

					$acl[] = 'extended';
					$acl[] = $action;

					switch($protoApp['protocol'])
					{
						case 'icmp': {
							$acl[] = ($srcAdd['IPv'] === 4) ? ('icmp') : ('icmp6');
							break;
						}
						case 'icmp4':
						{
							if($srcAdd['IPv'] === 4) {
								$acl[] = 'icmp';
							}
							else {
								continue(2);
							}

							break;
						}
						case 'icmp6':
						{
							if($srcAdd['IPv'] === 6) {
								$acl[] = 'icmp6';
							}
							else {
								continue(2);
							}

							break;
						}
						default: {
							$acl[] = $protoApp['protocol'];
						}
					}

					foreach(array($srcAdd, $dstAdd) as $address)
					{
						switch($address['name'])
						{
							case 'any':
							case 'any4':
							case 'any6': {
								$acl[] = $address['name'];
								break;
							}
							default: {
								$acl[] = 'object';
								$acl[] = $address['name'];
							}
						}
					}
					
					if(array_key_exists('options', $protoApp))
					{
						switch($protoApp['protocol'])
						{
							case 'tcp':
							case 'udp': {
								$acl[] = (count($protoApp['options']) > 1) ? ('range') : ('eq');
								$acl[] = implode(' ', $protoApp['options']);
								break;
							}
							case 'icmp':
							case 'icmp4':
							case 'icmp6':
							{
								if(array_key_exists('type', $protoApp['options']))
								{
									$acl[] = $protoApp['options']['type'];

									if(array_key_exists('code', $protoApp['options'])) {
										$acl[] = $protoApp['options']['code'];
									}
								}
							}
						}
					}

					if(!$accessList['state']) {
						$acl[] = 'inactive';
					}

					if($accessList['description'] !== '')
					{
?>
access-list ACL_NEW_<?php echo $accessList['aclName']; ?> remark <?php echo $accessList['description']; ?>  
<?php
					}
?>
access-list ACL_NEW_<?php echo $accessList['aclName']; ?> <?php echo implode(' ', $acl); ?>  
<?php
				}
			}
		}

		echo PHP_EOL;
	}
?>

access-list ACL_DAP_All-deny extended deny ip any any

<?php
	echo PHP_EOL.PHP_EOL;

	foreach($aclNames as $aclName)
	{
?>

clear configure access-list ACL_OLD_<?php echo $aclName; ?>  
access-list ACL_<?php echo $aclName; ?> rename ACL_OLD_<?php echo $aclName; ?>  
access-list ACL_NEW_<?php echo $aclName; ?> rename ACL_<?php echo $aclName; ?>  

<?php
	}

	echo PHP_EOL.PHP_EOL;

	foreach($this->dap as $dap)
	{
?>

dynamic-access-policy-record DAP_<?php echo $dap['name']; ?>
<?php
		foreach($dap['acl'] as $aclName)
		{
?>

  network-acl ACL_<?php echo $aclName; ?>  
  no network-acl ACL_OLD_<?php echo $aclName; ?>
<?php
		}
?>

  priority <?php echo $dap['priority']; ?>  
exit
<?php
	}
?>

dynamic-access-policy-record DAP_All-Deny
  network-acl ACL_DAP_All-deny
  priority 0
exit