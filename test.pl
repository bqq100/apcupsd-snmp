#!/usr/bin/perl -w
use strict;
use warnings;

# TODO Extend to make the tests run usig Test::More, so that they can be run with prove.
# TODO Extend tests to cover more cases
# TODO Mock apcupsd so we can test more cases and comms failures

use NetSNMP::agent qw( MODE_GET MODE_GETNEXT );
use NetSNMP::OID ();

my $base_oid = NetSNMP::OID->new('.1.3.6.1.4.1.318.1.1.1');

my $test_data = [
    #OID, MODE
    ['1.1.1.0',  MODE_GET,     ], # upsBasicIdentModel
    ['1.1.1',    MODE_GET,     ], # upsBasicIdentModel with missing .0
    ['2.2.2.0',  MODE_GET,     ], # upsAdvBatteryTemperature - ITEMP not returned by my UPS

    ['1.1.1.0',  MODE_GETNEXT, ], # upsBasicIdentModel -> upsBasicIdentName
    ['.1.3.6.1', MODE_GETNEXT, ], # OID below our first OID -> should return the first one
    ['.1.3.5.1', MODE_GETNEXT, ], # OID below our first OID -> should return the first one
    ['12',       MODE_GETNEXT, ], # OID after our last OID -> should return an error
];
our $agent = MyTestAgent->new(); # Essential that this is in global scope (i.e. $main::agent = ... )

{
    no warnings qw(once);
    #    $mod_apcupsd::debugging = 1;
}

do './mod_apcupsd.pl';
print STDERR "## mod_apcupsd loaded\n";

for my $test (@$test_data) {
    $agent->dispatch($base_oid, @$test);
}
die "## DONE";


package MyTestAgent;

sub new {
    my ($class) = @_;
    return bless {}, $class;
}

sub register {
    my ($self, $name, $oid, $handler) = @_;

    print STDERR "## Agent register() called: $name, $oid, $handler\n";

    $self->{name} = $name;
    $self->{oid} = $oid;
    $self->{handler} = $handler;

    return 1;
}

sub dispatch {
    my($self, $base_oid, $oid_ext, $mode) = @_;

    my $req_oid;
    if($oid_ext =~ /^\./) {
        $req_oid = NetSNMP::OID->new($oid_ext);
    }
    else {
        $req_oid = $base_oid + $oid_ext;
    }

    print STDERR "## Issuing request for $req_oid of type $mode\n";
    my $reg_info = MyTestRegInfo->new($self->{oid});
    my $req_info = MyTestReqInfo->new($mode);
    my $request  = MyTestRequest->new($req_oid);
    my $result   = $self->{handler}->($self->{handler}, $reg_info, $req_info, $request);
    if($request->{error}) {
        print STDERR "## Got result for " . $request->getOID() . " with error: " . $request->getError() . "\n";
    }
    else {
        print STDERR "## Got result for " . $request->getOID() . " with value: " . $request->getValue() . "\n";
    }

    return $result;
}

package MyTestRegInfo;

sub new {
    my ($class, $base_oid) = @_;
    return bless { base_oid => NetSNMP::OID->new("$base_oid")}, $class;
}

sub getRootOID {
    my ($self) = @_;
    return $self->{base_oid};
}

package MyTestReqInfo;

sub new {
    my ($class, $mode) = @_;
    return bless { mode => $mode}, $class;
}

sub getMode {
    my ($self) = @_;
    return $self->{mode};
}

package MyTestRequest;

sub new {
    my ($class, $oid) = @_;
    return bless { oid => $oid}, $class;
}

sub getOID {
    my ($self) = @_;
    return $self->{oid};
}

sub setOID {
    my ($self, $oid) = @_;
    $self->{oid} = $oid;
    return $oid;
}

sub getValue {
    my ($self) = @_;
    return $self->{value};
}

sub setValue {
    my ($self, $type, $value) = @_;
    $self->{value} = $value;
    return $value;
}

sub getError {
    my ($self) = @_;
    return $self->{error};
}

sub setError {
    my ($self, $info, $error) = @_;
    $self->{error} = $error;
    return $error;
}

sub next {
    my ($self) = @_;
    return undef;
}

