###############################################################################
# Copyright (c) 2011 Jakub Jirutka (jakub@jirutka.cz)
# Copyright (c) 2020 Robert May (robertmay@cpan.org)
#
# This program is free software: you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the  GNU Lesser General Public License for
# more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

###############################################################################
#
#                        Net-SNMP module for apcupsd
#
#
# Net-SNMP module for monitoring APC UPSes without SNMP support. It reads output 
# from apcupsd and writes it into appropriate OIDs like UPSes 
# with built-in SNMP support, but with rather less detail.
# 
# To load this into a running net-snmp snmpd agent with embedded perl support
# turned on, simply put the following line to your snmpd.conf file:
#
#   perl do "/path/to/mod_apcupsd.pl";
#
# Net-snmp must be compiled with Perl support and apcupsd properly configured 
# and running! apcupsd must be running with its NIS function enabled and
# accessible from the host running snmpd (as if getting /sbin/apcaccess to run).
# http://www.apcupsd.org/manual/manual.html#apcaccess
#
# You can download v4.3.2 MIB file of PowerNet (APC) from 
# https://www.apc.com/shop/uk/en/products/PowerNet-MIB-v4-3-2/P-SFPMIB432

# We use a package to give us our own namesace and so as not to pollute the
# Main:: namespace which is shared by all embedded extensions.  We'll use
# package variables with checks for defined-ness for the
# config variables so that they can be set in the snmpd.conf file as
#
# perl $mod_apcupsd::<variable> = <value>;
#
#
package mod_apcupsd;

use strict;
use warnings;

BEGIN {
    print STDERR "Loading mod_apcupsd into snmpd\n";
}

use NetSNMP::agent qw( MODE_GET MODE_GETNEXT MODE_GETBULK SNMP_ERR_NOSUCHNAME SNMP_ERR_READONLY);
use NetSNMP::OID     ();
use NetSNMP::ASN   qw(ASN_OCTET_STR ASN_TIMETICKS ASN_GAUGE ASN_INTEGER );
use IO::Socket::INET ();
use IO::Select ();

#################################################
#################### SETTINGS ###################
#################################################

# Set to 1 to get extra debugging information.
our $debugging //= 0; # in snmpd.conf: perl $mod_apsupcd::debugging = 1;

# How often fetch data from apcupsd (in seconds)?
# This is the maximum rate at which we'll call apcupsd to get new data.  If your
# SNMP manager is polling for data then remember to sum this value and the polling
# interval of you snmp manager plus teh polling interval for apsupsd to the UPS itself
# to get the worst-case propogation delay
our $fetch_interval //= 20; # in snmpd.conf: perl $mod_apsupcd::fetch_interval = 30;

# host or ip address and port of the machine hosting the apcupsd instance we want to talk
# to.  Ensure the NIS server is set up to accept remote connections.
our $peer_host //= '127.0.0.1'; # in snmpd.conf: perl $mod_apsupcd::peer_host = "ups.example.com";
our $peer_port //= 3551;        # in snmpd.conf: perl $mod_apsupcd::peer_port = 3551;

#################################################
#################### Mappings ###################
#################################################
# set up all the mappings and conversions between
# apcupsd status report fields and SNMP OIDs

use constant {
    TICKS_PER_SEC => 100,
    TICKS_PER_MIN => 6000,
};

# Base OID of APC UPS tree to hook onto.
my $base_oid = NetSNMP::OID->new('.1.3.6.1.4.1.318.1.1.1');

# OIDs mapping
# TODO identify the static data and don't fetch each time it's requested?
my $mapping = [
#   Apcupsd name OID suffix  Data type      Conversion        OID name
    ['MODEL',    '1.1.1.0',  ASN_OCTET_STR, \&to_str,      ], # upsBasicIdentModel
    ['UPSNAME',  '1.1.2.0',  ASN_OCTET_STR, \&to_str,      ], # upsBasicIdentName
    ['FIRMWARE', '1.2.1.0',  ASN_OCTET_STR, \&to_str,      ], # upsAdvIdentFirmwareRevision
    ['SERIALNO', '1.2.3.0',  ASN_OCTET_STR, \&to_str,      ], # upsAdvIdentSerialNumber

    ['TONBATT',  '2.1.2.0',  ASN_TIMETICKS, \&sec_to_tt,   ], # upsBasicBatteryTimeOnBattery
    ['BATTDATE', '2.1.3.0',  ASN_OCTET_STR, \&to_date,     ], # upsBasicBatteryLastReplaceDate
    ['BCHARGE',  '2.2.1.0',  ASN_GAUGE,     \&to_int,      ], # upsAdvBatteryCapacity
    ['ITEMP',    '2.2.2.0',  ASN_GAUGE,     \&to_int,      ], # upsAdvBatteryTemperature TODO should be clamped to be 0 or above
    ['TIMELEFT', '2.2.3.0',  ASN_TIMETICKS, \&min_to_tt,   ], # upsAdvBatteryRunTimeRemaining
    ['NOMBATTV', '2.2.7.0',  ASN_INTEGER,   \&to_int,      ], # upsAdvBatteryNominalVoltage
    ['BATTV',    '2.2.8.0',  ASN_INTEGER,   \&to_int,      ], # upsAdvBatteryActualVoltage
    ['BCHARGE',  '2.3.1.0',  ASN_GAUGE,     \&to_hpint,    ], # upsHighPrecBatteryCapacity
    ['ITEMP',    '2.3.2.0',  ASN_GAUGE,     \&to_hpint,    ], # upsHighPrecBatteryTemperature TODO should be clamped to be 0 or above
    ['NOMBATTV', '2.3.3.0',  ASN_INTEGER,   \&to_hpint,    ], # upsHighPrecBatteryNominalVoltage
    ['BATTV',    '2.3.4.0',  ASN_INTEGER,   \&to_hpint,    ], # upsHighPrecBatteryActualVoltage
    ['ITEMP',    '2.3.13.0', ASN_GAUGE,     \&to_hpint,    ], # upsHighPrecExtdBatteryTemperature

    ['LINEV',    '3.2.1.0',  ASN_GAUGE,     \&to_int,      ], # upsAdvInputLineVoltage
    ['LINEFREQ', '3.2.4.0',  ASN_GAUGE,     \&to_int,      ], # upsAdvInputFrequency
    ['LASTXFER', '3.2.5.0',  ASN_INTEGER,   \&to_lf_cause, ], # upsAdvInputLineFailCause
    ['LINEV',    '3.3.1.0',  ASN_GAUGE,     \&to_hpint,    ], # upsHighPrecInputLineVoltage
    ['LINEFREQ', '3.3.4.0',  ASN_GAUGE,     \&to_hpint,    ], # upsHighPrecInputFrequency

    ['STATUS',   '4.1.1.0',  ASN_INTEGER,   \&to_status,   ], # upsBasicOutputStatus
    ['OUTPUTV',  '4.2.1.0',  ASN_GAUGE,     \&to_int,      ], # upsAdvOutputVoltage
    ['LOADPCT',  '4.2.3.0',  ASN_GAUGE,     \&to_int,      ], # upsAdvOutputLoad
    ['OUTPUTV',  '4.3.1.0',  ASN_GAUGE,     \&to_hpint,    ], # upsHighPrecOutputVoltage
    ['LOADPCT',  '4.3.3.0',  ASN_GAUGE,     \&to_hpint,    ], # upsHighPrecOutputLoad

    ['NOMOUTV',  '5.2.1.0',  ASN_INTEGER,   \&to_int,      ], # upsAdvConfigRatedOutputVoltage
    ['HITRANS',  '5.2.2.0',  ASN_INTEGER,   \&to_int,      ], # upsAdvConfigHighTransferVolt
    ['LOTRANS',  '5.2.3.0',  ASN_INTEGER,   \&to_int,      ], # upsAdvConfigLowTransferVolt
    ['ALARMDEL', '5.2.4.0',  ASN_INTEGER,   \&to_alarm,    ], # upsAdvConfigAlarm
    ['RETPCT',   '5.2.6.0',  ASN_INTEGER,   \&to_int,      ], # upsAdvConfigMinReturnCapacity
    ['SENSE',    '5.2.7.0',  ASN_INTEGER,   \&to_sense,    ], # upsAdvConfigSensitivity
    ['DWAKE',    '5.2.9.0',  ASN_TIMETICKS, \&sec_to_tt,   ], # upsAdvConfigReturnDelay
    ['DSHUTD',   '5.2.10.0', ASN_TIMETICKS, \&sec_to_tt,   ], # upsAdvConfigShutoffDelay

    ['STESTI',   '7.2.1.0',  ASN_INTEGER,   \&to_sched,    ], # upsAdvTestDiagnosticSchedule
    ['SELFTEST', '7.2.3.0',  ASN_INTEGER,   \&to_diag,     ], # upsAdvTestDiagnosticsResults

    ['STATFLAG', '11.1.1.0', ASN_OCTET_STR, \&to_flags,    ], # upsBasicStateOutputState FIXME currently retuns all '0's

    # Here's a list of all the possible things that can be returned from apcupsd, but don't
    # appear above and haven't been considered yet:
    # TODO: DATE HOSTNAME CABLE UPSMODE STARTTIME MBATTCHG MINTIMEL MAXTIME MAXLINEV MINLINEV DLOWBATT NUMXFERS XONBATT
    #       CUMONBATT XOFFBAT STATFLAG DIPSW REG1 REG2 REG3 MANDATE NOMINV NOMPOWER HUMIDITY AMBTEMP EXTBATTS BADBATTS
    #
    # DONE: APC UPSNAME VERSION MODEL STATUS LINEV LOADPCT BCHARGE TIMELEFT OUTPUTV SENSE DWAKE DSHUTD LOTRANS HITRANS RETPCT
    #       ITEMP ALARMDEL BATTV LINEFREQ LASTXFER TONBATT SELFTEST STESTI SERIALNO BATTDATE NOMOUTV NOMBATTV FIRMWARE
    #       APCMODEL
    #
    # Obvious OIDS to add support for: TODO upsBasicBatteryStatus
];

sub to_str {
    return "$_[0]";
}

sub to_date {
    # Convert YYY-MM-DD to mm/dd/yyyy as dictated by the MIB description
    my($y, $m, $d) = split('-',$_[0]);
    $y += 2000 if $y < 100; # TODO Assumes we have no batteries more than 20 years old? Is there a better answer?
    return sprintf("%02d/%02d/%04d", $m, $d, $y);;
}

sub to_int {
    return int(0 + $_[0]);
}

sub to_hpint {
    return int(10 * $_[0]);
}

sub sec_to_tt {
    return int($_[0] * TICKS_PER_SEC);
}

sub min_to_tt {
    return int($_[0] * TICKS_PER_MIN);
}

sub to_lf_cause {
    # LASTXFER => upsAdvInputLineFailCause
    my $options = { # From lib/apcstatus.c
        'No transfers since turnon'         => 1,   # noTransfer
        'High line voltage'                 => 2,   # highLineVoltage
        'Low line voltage'                  => 4,   # blackout
        'Line voltage notch or spike'       => 8,   # largeMomentarySpike
        'Automatic or explicit self test'   => 9,   # selfTest
        'Unacceptable line voltage changes' => 10,  # rateOfVoltageChange
        'Forced by software'                => undef,
        'Input frequency out of range'      => undef,
        'UNKNOWN EVENT'                     => undef,
    };
    my $r = $options->{$_[0]};

    return (defined $r ? $r : 0);
}

sub to_alarm {
    # ALARMDEL => upsAdvConfigAlarm
    my $options = { # From lib/apcstatus.c
        '30'          => 1,   # timed
        '5'           => 1,   # timed
        'Always'      => 1,   # timed
        'Low Battery' => 2,   # atLowBattery
        'No alarm'    => 3    # never
    };
    my $r = $options->{$_[0]};

    return (defined $r ? $r : 0);
}

sub to_sense {
    # SENSE => upsAdvConfigSensitivity
    my $options = { # From lib/apcstatus.c
        'Auto Adjust'   => 1,   # auto
        'Low'           => 2,   # low
        'Medium'        => 3,   # medium
        'High'          => 4,   # high
        'Unknown'       => undef,
    };
    my $r = $options->{$_[0]};

    return (defined $r ? $r : 0);
}

sub to_schedule {
    # STESTI => upsAdvTestDiagnosticSchedule
    my $options = {
        'None'  => 1,   # unknown
        '336'   => 2,   # biweekly
        '168'   => 3,   # weekly
        'ON'    => 4,   # atTurnOn
        'OFF'   => 5    # never
    };
    my $r = $options->{$_[0]};

    return (defined $r ? $r : 0);
}

sub to_diag {
    # SELFTEST => upsAdvTestDiagnosticsResults
    my $options = { # From lib/apcstatus.c
        'OK'    => 1,   # ok
        'BT'    => 2,   # failed
        'NG'    => 3,   # invalidTest
        'IP'    => 4,   # testInProgress
        'NO'    => undef,   # ! NONE
        'WN'    => undef,   # ! WARNING
        '??'    => undef    # ! UNKNOWN 
    };
    my $r = $options->{$_[0]};

    return (defined $r ? $r : 0);
}

sub to_status {
    # STATUS => upsBasicOutputStatus
    #
    # From lib/apcstatus.c is seems that STATUS is a space seperated set of words from this
    # set:
    # CAL TRIM BOOST ONLINE ONBATT OVERLOAD LOWBATT REPLACEBATT NOBATT SLAVE SLAVEDOWN
    # COMMLOST 'SHUTTING DOWN'
    #
    # and we need to map into one of these from v4.3.2 of the APC powernet MIB:
    #
    # unknown(1), onLine(2), onBattery(3), onSmartBoost(4), timedSleeping(5),
    # softwareBypass(6), off(7), rebooting(8), switchedBypass(9), hardwareFailureBypass(10),
    # sleepingUntilPowerReturn(11), onSmartTrim(12), ecoMode(13), hotStandby(14),
    # onBatteryTest(15), emergencyStaticBypass(16), staticBypassStandby(17),
    # powerSavingMode(18), spotMode(19), eConversion(20), chargerSpotmode(21),
    # inverterSpotmode(22), activeLoad(23), batteryDischargeSpotmode(24), inverterStandby (25),
    # chargerOnly(26)
    #
    # TODO Might be better to generate this from STATFLAG

    # As we can only choose one, and I don't know what combinations are valid I've tried
    # to us the most likley and chosen the first one to be found
    if($_[0] =~ /ONLINE/) {
        return 2; #onLine
    }
    if($_[0] =~ /ONBATT/) {
        return 3; #onBattery
    }
    if($_[0] =~ /BOOST/) {
        return 4; #onSmartBoost
    }
    if($_[0] =~ /TRIM/) {
        return 12; #onSmartTrim
    }

    return 1; # unknown
}

sub to_flags {
    # STATFLAG => upsBasicStateOutputState
    #
    # According to the mib this is a string of 64 '0' or '1' characters,
    # FIXME map STATFLAG and any other data we have into the 64 bits
    
    #   /* bit values for APC UPS Status Byte (ups->Status) */
    #define UPS_calibration   0x00000001
    #define UPS_trim          0x00000002
    #define UPS_boost         0x00000004
    #define UPS_online        0x00000008
    #define UPS_onbatt        0x00000010
    #define UPS_overload      0x00000020
    #define UPS_battlow       0x00000040
    #define UPS_replacebatt   0x00000080

    #   /* Extended bit values added by apcupsd */
    #define UPS_commlost      0x00000100    /* Communications with UPS lost */
    #define UPS_shutdown      0x00000200    /* Shutdown in progress */
    #define UPS_slave         0x00000400    /* Set if this is a slave */
    #define UPS_slavedown     0x00000800    /* Slave not responding */
    #define UPS_onbatt_msg    0x00020000    /* Set when UPS_ONBATT message is sent */
    #define UPS_fastpoll      0x00040000    /* Set on power failure to poll faster */
    #define UPS_shut_load     0x00080000    /* Set when BatLoad <= percent */
    #define UPS_shut_btime    0x00100000    /* Set when time on batts > maxtime */
    #define UPS_shut_ltime    0x00200000    /* Set when TimeLeft <= runtime */
    #define UPS_shut_emerg    0x00400000    /* Set when battery power has failed */
    #define UPS_shut_remote   0x00800000    /* Set when remote shutdown */
    #define UPS_plugged       0x01000000    /* Set if computer is plugged into UPS */
    #define UPS_battpresent   0x04000000    /* Indicates if battery is connected */
    
    # Our input shoudl look like 0x12345678
    #if($_[0] =~ /^0x([A-Fa-f0-9]{4})([A-Fa-f0-9]{4})$/) {
        # As some perls still don't handle 64 bit ints well we split into 2 32 bit numbers
        # convert each into a "binary string", reverse teh strings and put them back together
        #    return reverse unpack('B32', pack('N', hex($2))) . reverse unpack('B32', pack('N', hex($1)));
        #}
    #else# {
    #return "UNKNOWN";
    #}

    return '0' x 64;
}

#################################################
################# Initialisation ################
#################################################

# Hashmap for apcupsd status field names => OIDs
# as a name may be used for more than one OID, each
# entry in this hash is an arrayref containing a
# list of OIDs
my %name_oid;

# Hashmap for OID info
# key is OID value is a hash ref with keys:
# - type => ASN-type
# - convert => sub ref to call to convert apcupsd value to SNMP value
my %oid_info;

# Build hashmaps
foreach my $row (@$mapping) {
    my ($name, $oid, $type, $conv) = @$row;
    $oid = $base_oid + $oid;
    $name_oid{$name} = [] unless exists $name_oid{$name};
    push @{$name_oid{$name}}, $oid;
    $oid_info{$oid} = {type => $type, convert => $conv};
}

# Timestamp of last data fetch
my $last_fetch = 0;

# Register in the master agent we're embedded in.
my $agent = $main::agent; # should be created for us in the right way by /usr/share/snmp/snmp_perl.pl
unless(defined $agent) {
    print STDERR "mod_apcupsd: No \$agent defined - giving up\n";
    die; # Will cause the do BLOCK to exit before we register with the agent
}
$agent->register('mod_apcupsd', $base_oid, \&snmp_handler);
print STDERR "mod_apcupsd: registered at $base_oid \n" if ($debugging);

#################################################
################### Subroutines #################
#################################################

# Fetch data from apsupcd and convert for SNMP.
# This routine caches the data returned and only
# re-queries if it's more than $fetch_interval
# seconds since the last fetch
{
    my $data = {};
    my $oid_chain = {};

    sub fetch_data {

        if ((time - $last_fetch) < $fetch_interval) {
            print STDERR "It's only " . (time-$last_fetch) . " sec since last update, interval is "
                    . "$fetch_interval\n" if ($debugging);
        }
        else {
            # Fetch the data from the apcupsd NIS server as documented
            # at http://www.apcupsd.org/manual/manual.html#apcaccess
            ######################################################################
            # This is approimately equivilent to the commandline
            # apcaccess -u status
            #
            my $re_units = '(Minutes|Seconds|Percent|Volts|Watts|Hz|C)$'; # units to remove from apcaccess.c

            my $socket = IO::Socket::INET->new(
                PeerHost => $peer_host,
                PeerPort => $peer_port,
                Proto    => 'tcp',
            ) or die "Error creating socket: $!";  # FIXME don't die, keep going

            # Sent our request
            $socket->send(pack('n/A*', 'status'));
            $socket->flush();

            # Wait until there's a response to read (timeout adfter 10 seconds)
            my $select = IO::Select->new();
            $select->add($socket);

            $!=0;
            my @ready = $select->can_read(10);

            if(@ready) { # There's something to read
                # TODO Should check that it's our socket ready to read from?
                my $new_data = {};
                my @oid_list;
line:    
                while(defined $socket->recv(my $line, 1024)) { # TODO Do we need to timout here or does recv always fail on network errors?

                    for my $item (unpack("(n/A*)*", $line)) {
                        if(length $item > 0) {
                            # Remove any units
                            $item =~ s/ $re_units//;
                            # split into name and value
                            my($name, $value) = split(/\s+:\s+/, $item);
                            # Store in new_data
                            for my $oid (@{$name_oid{$name}}) {
                                $new_data->{$oid} = $oid_info{$oid}->{convert}->($value);
                                push @oid_list, $oid;
                            }
                        }
                        else {
                            # Data sent ends with a zero length block
                            # successfully completed getting data
                            $last_fetch = time();

                            # Update the cached data
                            $data = $new_data;

                            # Build our oid-chain for servicing getnext
                            # Chain of our OIDs in lexical order for GETNEXT

                            # new OID chain
                            $oid_chain = {};

                            # Build OID chain
                            my $prev_oid = 0;
                            foreach my $oid (sort {$a <=> $b} @oid_list) {
                                $oid_chain->{$prev_oid} = $oid;
                                $prev_oid = $oid;
                            }
                            # ... and we're done
                            last line;
                        }
                    }
                }
            }
            elsif ($! == 0) { # Timeout
                print STDERR "mod_apcupsd: Timed out waiting for response from apcupsd\n";
            }
            else {
                print STDERR "mod_apcupsd: Error while wating to read socket: $!";
            }

            $socket->close();
        }
        # If we're having problems communicating with apcupsd and our cached data
        # is really old then we should stop using it
        # TODO how long is 'really old' - make it a config item?
        if((time() - $last_fetch) > (10 * $fetch_interval)) {
            $data = {}; $oid_chain = {};
            print STDERR "mod_apcupsd: No comms with apcupsd in a long time.  Discarding cached data\n";
        }
        return $data, $oid_chain;
    }
}

# Subroutine that handle the incoming requests to our part of the OID tree.  
# This subroutine will get called for all requests within the OID space 
# under the registration oid made above.
sub snmp_handler {
    my ($handler, $registration_info, $request_info, $requests) = @_;

    # Get the data from apcupsd:
    my ($data, $oid_chain) = fetch_data();

    my $mode = $request_info->getMode();
    print STDERR "Processing a request of type $mode\n" if ($debugging);

    for(my $request = $requests; $request; $request = $request->next()) {
        my $oid = $request->getOID();
        print STDERR "Processing request for $oid\n" if ($debugging);

        if ($mode == MODE_GET) {
            # Mode GET (for single entry)
            
            if (exists($data->{$oid})) {
                my $value = $data->{$oid};

                print STDERR "  GET Returning: $value\n" if ($debugging);
                $request->setValue($oid_info{$oid}->{type}, $value);
            }
            elsif (exists($data->{"$oid.0"})) {
                # Workaround for requests without "index" TODO: do we really need this?
                my $new_oid = $oid + '.0';
                my $value = $data->{$new_oid};

                print STDERR "  GET Returning for $new_oid: $value\n" if ($debugging);
                $request->setOID($new_oid);
                $request->setValue($oid_info{$new_oid}->{type}, $value);
            }
            else {
                print STDERR " GET No value ...\n" if $debugging;
                $request->setError($request_info, SNMP_ERR_NOSUCHNAME);
            }
        }
        elsif ($mode == MODE_GETNEXT) {
            my $next_oid = $oid_chain->{0};
                
            # Walk the OID chain to find the next OID we can return
            while ($next_oid && ($oid >= $next_oid)) {
                $next_oid = $oid_chain->{$next_oid};
            }
            if($next_oid) {
                my $value = $data->{$next_oid};

                print STDERR "  GETNEXT Returning next OID $next_oid: $value\n" if ($debugging);
                $request->setOID($next_oid);
                $request->setValue($oid_info{$next_oid}->{type}, $value);
            }
            else {
                print STDERR " GETNEXT No next value ...\n" if $debugging;
                # TODO What is the right error to return when we walk off the end of the chain?
                # Should it be passe dback to snmpd to resolve?  If yes, then how?
                # possilbe that this isn't an error and we just dont return a value??
                $request->setError($request_info, SNMP_ERR_NOSUCHNAME);
            }
        }
        elsif ($mode == MODE_GETBULK) {
            # TODO For now ignoring this, as if I understand correctly we
            # shouldn't be passed a bulk requestm, but snmpd should break it
            # into multiple Get requests for us.
        }
        else {
            # It's a MODE_SET* command that we don't support
            if (exists($data->{$oid})) {
                # TODO is this the right error to return?
                $request->setError($request_info, SNMP_ERR_READONLY);
            }
            else {
                # It's not an OID we know about
                $request->setError($request_info, SNMP_ERR_NOSUCHNAME);
            }
        }
    }

    print STDERR "Processing finished\n" if ($debugging);
}
