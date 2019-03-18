<?php
/**
  * /!\ La balise de fermeture de PHP '?>' supprime le saut de ligne qui la suit immédiatement
  * Un double saut de ligne est le workaround le plus simple à mettre en place
  */

	namespace App\Firewall;

	use App\Firewall\Core;
?>

applications
{
<?php
	foreach($this->applications as $protocol)
	{
?>
	application <?php echo $protocol['name']; ?>

	{
<?php
		if($protocol['protocol'] === 'ip')
		{
?>
		term TCP protocol tcp;
		term UDP protocol udp;
		term ICMP protocol icmp;
<?php
		}
		else
		{
?>
		protocol <?php echo $protocol['protocol']; ?>;
<?php
			if(array_key_exists('options', $protocol))
			{
				switch($protocol['protocol'])
				{
					case 'icmp':
					case 'icmp4':
					case 'icmp6':
					{
						if(array_key_exists('type', $protocol['options']))
						{
							$icmpType = ($protocol['protocol'] === 'icmp6') ? ('icmp6-type') : ('icmp-type');
?>
		<?php echo $icmpType.' '.$protocol['options']['type']; ?>;
<?php
							if(array_key_exists('code', $protocol['options']))
							{
								$icmpCode = ($protocol['protocol'] === 'icmp6') ? ('icmp6-code') : ('icmp-code');
?>
		<?php echo $icmpCode.' '.$protocol['options']['code']; ?>;
<?php
							}
						}

						break;
					}
					default:
					{
?>
		destination-port <?php echo $protocol['options']; ?>;
<?php
					}
				}
			}
		}
?>
	}
<?php
	}
?>
}
security
{
	zones
	{
<?php
	foreach($this->addressBook as $zone => $addresses)
	{
?>
		security-zone <?php echo $zone; ?>

		{
			address-book
			{
<?php
		foreach($addresses as $items)
		{
			// IPv4 & IPv6
			foreach($items as $address)
			{
				if(array_key_exists('__doNotCreateAdd__', $address) && $address['__doNotCreateAdd__']) {
					continue;
				}
?>
				address <?php echo $address['name'].' '.$address['address']; ?>;
<?php
			}
		}
?>
			}
		}
<?php
	}
?>
	}
	policies
	{
<?php
	foreach($this->accessLists as $accessList)
	{
?>
		from-zone <?php echo $accessList['srcZone']; ?> to-zone <?php echo $accessList['dstZone']; ?>

		{
			policy <?php echo $accessList['aclName']; ?>

			{
				description "<?php echo $accessList['description']; ?>";
				match {
					source-address [ <?php echo implode(' ', $accessList['srcAdds']); ?> ];
					destination-address [ <?php echo implode(' ', $accessList['dstAdds']); ?> ];
					application [ <?php echo implode(' ', $accessList['protoApps']); ?> ];
				}
				then {
					<?php echo ($accessList['action']) ? ('permit;') : (''); ?>

					log {               
						session-init;
						session-close;
					}
					count;
				}
			}
		}
<?php
	}
?>
	}
}