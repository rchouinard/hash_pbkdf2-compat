<?php

namespace Rych;

use PHPUnit_Framework_TestCase as TestCase;

class HashPBKDF2Test extends TestCase
{

    public function rfc6070vectors()
    {
        return array (
            array (array (
                'algo' => 'sha1',
                'password' => 'password',
                'salt' => 'salt',
                'iterations' => 1,
                'length' => 20,
                'result' => '0c60c80f961f0e71f3a9',
                'raw_result' => '0c60c80f961f0e71f3a9b524af6012062fe037a6',
            )),
            array (array (
                'algo' => 'sha1',
                'password' => 'password',
                'salt' => 'salt',
                'iterations' => 2,
                'length' => 20,
                'result' => 'ea6c014dc72d6f8ccd1e',
                'raw_result' => 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957',
            )),
            array (array (
                'algo' => 'sha1',
                'password' => 'password',
                'salt' => 'salt',
                'iterations' => 4096,
                'length' => 20,
                'result' => '4b007901b765489abead',
                'raw_result' => '4b007901b765489abead49d926f721d065a429c1',
            )),
            array (array (
                'algo' => 'sha1',
                'password' => 'passwordPASSWORDpassword',
                'salt' => 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
                'iterations' => 4096,
                'length' => 25,
                'result' => '3d2eec4fe41c849b80c8d8366',
                'raw_result' => '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
            )),
            array (array (
                'algo' => 'sha1',
                'password' => "pass\0word",
                'salt' => "sa\0lt",
                'iterations' => 4096,
                'length' => 16,
                'result' => '56fa6aa75548099d',
                'raw_result' => '56fa6aa75548099dcc37d7f03425e0c3',
            )),
        );
    }

    /**
     * @dataProvider rfc6070vectors
     * @test
     */
    public function testHashPbkdf2Function(Array $vector)
    {
        $this->assertEquals($vector['result'], \Rych\hash_pbkdf2($vector['algo'], $vector['password'], $vector['salt'], $vector['iterations'], $vector['length'], false));
        $this->assertEquals($vector['raw_result'], \bin2hex(\Rych\hash_pbkdf2($vector['algo'], $vector['password'], $vector['salt'], $vector['iterations'], $vector['length'], true)));
    }

}

