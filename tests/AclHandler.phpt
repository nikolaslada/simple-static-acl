<?php
declare(strict_types=1);

use NikolasLada\SimpleStaticAcl;
use Tester\Assert;


require __DIR__ . '/bootstrap.php';
require __DIR__ . '/../src/AclMutable.php';
require __DIR__ . '/../src/AclHandler.php';

$aclMutable = new SimpleStaticAcl\AclMutable;
$aclHandler = new SimpleStaticAcl\AclHandler($aclMutable);

$aclHandler->addType('web');
$aclHandler->addType('api');

$aclHandler->addRole('guest');
$aclHandler->addRole('user', 'guest');
$aclHandler->addRole('userB', 'guest');

$aclHandler->addResource('article');
$aclHandler->addResource('tag');
$aclHandler->addResource('group');


$aclHandler->setType('web');
$aclHandler->setRole('guest');
$aclHandler->setResource('article');
$aclHandler->allow('detail');

$aclHandler->setType(SimpleStaticAcl\AclHandler::ALL);
$aclHandler->setRole('user');
$aclHandler->allow('add');

$aclHandler->setRole('guest');
$aclHandler->setResource('tag');
$aclHandler->allow();

$aclHandler->setRole('userB');
$aclHandler->deny('extra');

Assert::same(
  [
      'web' => [
          'guest' => [
              'article' => [
                  'detail' => true,
              ],
              'tag' => [
                  '' => true,
              ],
          ],
          'user' => [
              'article' => [
                  'detail' => true,
                  'add' => true,
              ],
              'tag' => [
                  '' => true,
              ],
          ],
          'userB' => [
              'article' => [
                  'detail' => true,
              ],
              'tag' => [
                  '' => true,
              ],
          ],
      ],
      'api' => [
          'user' => [
              'article' => [
                  'add' => true,
              ],
              'tag' => [
                  '' => true,
              ],
          ],
          'guest' => [
              'tag' => [
                  '' => true,
              ],
          ],
          'userB' => [
              'tag' => [
                  '' => true,
              ],
          ],
      ]
  ],
  $aclHandler->getAcl()
);
