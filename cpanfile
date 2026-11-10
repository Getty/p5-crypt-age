requires 'perl', '5.010';

requires 'CryptX' => '0.067';
requires 'Moo';
requires 'namespace::clean';

on test => sub {
    requires 'Test::More';
};
