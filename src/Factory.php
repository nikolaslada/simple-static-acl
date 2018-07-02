<?php
declare(strict_types=1);

/**
 * This file is a part of the Simple Static ACL library.
 * Copyright (c) 2018 Nikolas Lada.
 * @author Nikolas Lada <nikolas.lada@gmail.com>
 */

namespace NikolasLada\SimpleStaticAcl;

class Factory {

  public function createAclImmutable(array $acl): AclImmutable {
    return new AclImmutable($acl);
  }
  
  public function unserializeAclImmutable(string $data): AclImmutable {
    return unserialize($data);
  }
  
}
