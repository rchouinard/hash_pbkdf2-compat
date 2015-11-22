<?php
/**
 * This file is part of Rych\hash_pbkdf2-compat
 *
 * (c) Ryan Chouinard <rchouinard@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Rych;

use PHPUnit_Framework_TestCase as TestCase;

class HashPBKDF2Test extends TestCase
{

    /**
     * Provides test vectors as defined in RFC 6070
     *
     * @return array
     */
    public function vectorProvider()
    {
        return array (
            // Extra test against GitHub PR #1
            array (array (
                'algo' => 'sha1',
                'password' => 'password',
                'salt' => 'salt',
                'iterations' => 1,
                'length' => 0, // Zero should default to the algo hash length
                'result' => '0c60c80f961f0e71f3a9b524af6012062fe037a6',
                'raw_result' => pack('H*', '0c60c80f961f0e71f3a9b524af6012062fe037a6'),
            )),
            array (array (
                'algo' => 'sha1',
                'password' => 'password',
                'salt' => 'salt',
                'iterations' => 1,
                'length' => 20,
                'result' => '0c60c80f961f0e71f3a9',
                'raw_result' => pack('H*', '0c60c80f961f0e71f3a9b524af6012062fe037a6'),
            )),
            array (array (
                'algo' => 'sha1',
                'password' => 'password',
                'salt' => 'salt',
                'iterations' => 2,
                'length' => 20,
                'result' => 'ea6c014dc72d6f8ccd1e',
                'raw_result' => pack('H*', 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957'),
            )),
            array (array (
                'algo' => 'sha1',
                'password' => 'password',
                'salt' => 'salt',
                'iterations' => 4096,
                'length' => 20,
                'result' => '4b007901b765489abead',
                'raw_result' => pack('H*', '4b007901b765489abead49d926f721d065a429c1'),
            )),
            array (array (
                'algo' => 'sha1',
                'password' => 'passwordPASSWORDpassword',
                'salt' => 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
                'iterations' => 4096,
                'length' => 25,
                'result' => '3d2eec4fe41c849b80c8d8366',
                'raw_result' => pack('H*', '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038'),
            )),
            array (array (
                'algo' => 'sha1',
                'password' => "pass\0word",
                'salt' => "sa\0lt",
                'iterations' => 4096,
                'length' => 16,
                'result' => '56fa6aa75548099d',
                'raw_result' => pack('H*', '56fa6aa75548099dcc37d7f03425e0c3'),
            )),
        );
    }

    /**
     * @test
     * @dataProvider vectorProvider
     */
    public function hash_pbkdf2_output(Array $vector)
    {
        $this->assertEquals($vector['result'], \Rych\hash_pbkdf2($vector['algo'], $vector['password'], $vector['salt'], $vector['iterations'], $vector['length'], false));
        $this->assertEquals($vector['raw_result'], \Rych\hash_pbkdf2($vector['algo'], $vector['password'], $vector['salt'], $vector['iterations'], $vector['length'], true));
    }

    /**
     * @test
     * @expectedException           \PHPUnit_Framework_Error_Warning
     * @expectedExceptionMessage    hash_pbkdf2() expects at least 4 parameters, 0 given
     */
    public function hash_pbkdf2_not_enough_arguments_error()
    {
        $this->assertNull(@\Rych\hash_pbkdf2());
        \Rych\hash_pbkdf2();
    }

    /**
     * @test
     * @expectedException           \PHPUnit_Framework_Error_Warning
     * @expectedExceptionMessage    hash_pbkdf2(): Unknown hashing algorithm: foobar
     */
    public function hash_pbkdf2_invalid_algorithm_error()
    {
        $this->assertFalse(@\Rych\hash_pbkdf2("foobar", "", "", 1));
        \Rych\hash_pbkdf2("foobar", "", "", 1);
    }

    /**
     * @test
     * @expectedException           \PHPUnit_Framework_Error_Warning
     * @expectedExceptionMessage    hash_pbkdf2() expects parameter 4 to be long, string given
     */
    public function hash_pbkdf2_iterations_type_error()
    {
        $this->assertNull(@\Rych\hash_pbkdf2("sha1", "", "", "string"));
        \Rych\hash_pbkdf2("sha1", "", "", "string");
    }

    /**
     * @test
     * @expectedException           \PHPUnit_Framework_Error_Warning
     * @expectedExceptionMessage    hash_pbkdf2(): Iterations must be a positive integer: 0
     */
    public function hash_pbkdf2_invalid_iterations_error()
    {
        $this->assertFalse(@\Rych\hash_pbkdf2("sha1", "", "", 0));
        \Rych\hash_pbkdf2("sha1", "", "", 0);
    }

    /**
     * @test
     * @expectedException           \PHPUnit_Framework_Error_Warning
     * @expectedExceptionMessage    hash_pbkdf2() expects parameter 5 to be long, string given
     */
    public function hash_pbkdf2_length_type_error()
    {
        $this->assertNull(@\Rych\hash_pbkdf2("sha1", "", "", 1, "string"));
        \Rych\hash_pbkdf2("sha1", "", "", 1, "string");
    }

    /**
     * @test
     * @expectedException           \PHPUnit_Framework_Error_Warning
     * @expectedExceptionMessage    hash_pbkdf2(): Length must be greater than or equal to 0: -1
     */
    public function hash_pbkdf2_invalid_length_error()
    {
        $this->assertFalse(@\Rych\hash_pbkdf2("sha1", "", "", 1, -1));
        \Rych\hash_pbkdf2("sha1", "", "", 1, -1);
    }

}
