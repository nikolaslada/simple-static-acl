<?php
declare(strict_types=1);

/**
 * This file is a part of the Simple Static ACL library.
 * Copyright (c) 2018 Nikolas Lada.
 * @author Nikolas Lada <nikolas.lada@gmail.com>
 */

namespace NikolasLada\SimpleStaticAcl;

class AclHandler {

  /** @var AclMutable */
  private $aclMutable;
  
  /**
   * For setters only.
   */
  
  /** @var string */
  private $type;
  /** @var array */
  private $typeList;
  /** @var string */
  private $role;
  /** @var array */
  private $roleList;
  /** @var string */
  private $resource;
  /** @var array */
  private $resourceList;
  
  
  public function __construct(AclMutable $aclMutable) {
    $this->aclMutable = $aclMutable;
  }
  
  /**
   * Setters.
   */
  
  public function setType(string $type): self {
    $this->type = $type;
    if (isset($this->typeList)) {
      unset($this->typeList);
    }
    
    return $this;
  }

  public function setTypeList(array $typeList): self {
    $this->typeList = $typeList;
    if (isset($this->type)) {
      unset($this->type);
    }
    
    return $this;
  }

  public function setRole(string $role): self {
    $this->role = $role;
    if (isset($this->roleList)) {
      unset($this->roleList);
    }
    
    return $this;
  }

  public function setRoleList(array $roleList): self {
    $this->roleList = $roleList;
    if (isset($this->role)) {
      unset($this->role);
    }
    
    return $this;
  }

  public function setResource(string $resource): self {
    $this->resource = $resource;
    if (isset($this->resourceList)) {
      unset($this->resourceList);
    }
    
    return $this;
  }

  public function setResourceList(array $resourceList): self {
    $this->resourceList = $resourceList;
    if (isset($this->resource)) {
      unset($this->resource);
    }
    
    return $this;
  }

  /**
   * Actions.
   */

  public function addType(string $type, string $parent): self {
    $this->aclMutable->addAccessType($type, $parent);
    return $this;
  }
  
  public function addRole(string $role, string $parent): self {
    $this->aclMutable->addRole($role, $parent);
    return $this;
  }
  
  public function addResource(string $resource, string $parent): self {
    $this->aclMutable->addResource($resource, $parent);
    return $this;
  }
  
  public function allow(string $privilege): self {
    $this->aclMutable->allow(
        $this->getTypes(),
        $this->getRoles(),
        $this->getResources(),
        [$privilege]
    );
    return $this;
  }
  
  public function allowList(array $privileges): self {
    $this->aclMutable->allow(
        $this->getTypes(),
        $this->getRoles(),
        $this->getResources(),
        $privileges
    );
    return $this;
  }
  
  public function deny(string $privilege): self {
    $this->aclMutable->deny(
        $this->getTypes(),
        $this->getRoles(),
        $this->getResources(),
        [$privilege]
    );
    return $this;
  }
  
  public function denyList(array $privileges): self {
    $this->aclMutable->deny(
        $this->getTypes(),
        $this->getRoles(),
        $this->getResources(),
        $privileges
    );
    return $this;
  }
  
  private function getTypes(): array {
    if (! (isset($this->type) && isset($this->typeList)) ) {
      throw new \DomainException;
    }
    
    if (isset($this->type)) {
      return [$this->type];
    } else {
      return $this->typeList;
    }
  }
  
  private function getRoles(): array {
    if (! (isset($this->role) && isset($this->roleList)) ) {
      throw new \DomainException;
    }
    
    if (isset($this->role)) {
      return [$this->role];
    } else {
      return $this->roleList;
    }
  }
  
  private function getResources(): array {
    if (! (isset($this->resource) && isset($this->resourceList)) ) {
      throw new \DomainException;
    }
    
    if (isset($this->resource)) {
      return [$this->resource];
    } else {
      return $this->resourceList;
    }
  }

}
