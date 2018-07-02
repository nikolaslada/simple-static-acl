<?php
declare(strict_types=1);

/**
 * This file is a part of the Simple Static ACL library.
 * Copyright (c) 2018 Nikolas Lada.
 * @author Nikolas Lada <nikolas.lada@gmail.com>
 */

namespace NikolasLada\SimpleStaticAcl;

class AclImmutable {

  /** @var array */
  private $acl;
  
  public function __construct(array $acl) {
    $this->acl = $acl;
  }
  
  public function isAllowed(string $type, string $role, string $resource, string $privilege): bool {
    if (isset($this->acl[$type][$role][$resource][AclHandler::ALL])) {
      return true;
    } elseif (isset($this->acl[$type][$role][$resource][$privilege])) {
      return true;
    } else {
      return false;
    }
  }

}
