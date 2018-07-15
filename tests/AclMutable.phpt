<?php
declare(strict_types=1);

use NikolasLada\SimpleStaticAcl;
use Tester\Assert;


require __DIR__ . '/bootstrap.php';
require __DIR__ . '/../src/AclMutable.php';
require __DIR__ . '/../src/AclHandler.php';

$aclMutable = new SimpleStaticAcl\AclMutable;

$aclMutable->addAccessType('web', \NULL);

$aclMutable->addRole('guest', \NULL);

$aclMutable->addResource('article', \NULL);

$aclMutable->allow(['web'], ['guest'], ['article'], ['detail']);

Assert::same(
  [
      'web' => [
          'guest' => [
              'article' => [
                  'detail' => true,
              ]
          ]
      ]
  ],
  $aclMutable->getAcl()
);

$aclMutable->deny([SimpleStaticAcl\AclHandler::ALL], ['guest'], ['article'], ['detail']);

Assert::same(
  [
      'web' => [
          'guest' => [
              'article' => [
                  'detail' => \NULL,
              ]
          ]
      ]
  ],
  $aclMutable->getAcl()
);
