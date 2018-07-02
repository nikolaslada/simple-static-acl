<?php
declare(strict_types=1);

/**
 * This file is a part of the Simple Static ACL library.
 * Copyright (c) 2018 Nikolas Lada.
 * @author Nikolas Lada <nikolas.lada@gmail.com>
 */

namespace NikolasLada\SimpleStaticAcl;

class AclFactory {

  const
    ALL = '',
    ALLOW = true,
    DENY = \NULL;

  /** @var array */
  private $accessTypes = [];
  
  /** @var array */
  private $roles = [];
  
  /** @var array */
  private $resources = [];
  
  /** @var array */
  private $acl = [];
  
  
  public function addAccessType(string $accessType, string $parent = \NULL): void {
    $this->accessTypes[$accessType] = $parent;
  }
  
  public function addRole(string $role, string $parent = \NULL): void {
    $this->roles[$role] = $parent;
  }
  
  public function addResource(string $resource, string $parent = \NULL): void {
    $this->resources[$resource] = $parent;
  }

  public function allow(string $accessType, string $role, string $resource, array $privileges): void {
    $this->setRights($accessType, $role, $resource, $privileges, self::ALLOW);
  }
  
  public function deny(string $accessType, string $role, string $resource, array $privileges): void {
    $this->setRights($accessType, $role, $resource, $privileges, self::DENY);
  }
  
  private function setRights(string $accessType, string $role, string $resource, array $privileges, ?bool $status): void {
    $accessTypeList = $this->getItemList($accessType, $this->accessTypes);
    $roleList = $this->getItemList($role, $this->roles);
    $resourceList = $this->getItemList($resource, $this->resources);
    
    foreach ($accessTypeList as $accessType) {
      foreach ($roleList as $role) {
        foreach ($resourceList as $resource) {
          $this->appendToAcl(
              $this->acl,
              [$accessType, $role, $resource, $privileges],
              $status
          );
        }
      }
    }
    
  }
  
  private function getItemList(string $code, array $resource): array {
    if ($code === self::ALL) {
      $list = array_keys($resource);
    } else {
      $list = [];
      $this->getItemWithDescendants($code, $resource, $list);
    }
    
    return $list;
  }
  
  private function getItemWithDescendants(string $code, array $resource, array $list): array {
    if (array_key_exists($code, $resource)) {
      $list[] = $code;
    } else {
      throw new \InvalidArgumentException;
    }
    
    foreach ($resource as $descendant => $ancestor) {
      if ($ancestor === $code) {
        $list = $this->getItemWithDescendants($descendant, $resource, $list);
      }
    }
    
    return $list;
  }

  private function appendToAcl(array & $acl, array $path, ?bool $status): ?bool {
    $current = current($path);
    if (count($path) > 1) {
      if (! isset( $acl[$current] ) ) {
        $acl[$current] = [];
      }

      return $this->appendToAcl($acl[$current], array_shift($path), $status);
    } else {
      if ($status === self::ALLOW) {
        $this->appendAllow($acl, $current);
      } else {
        $this->appendDeny($acl, $current);
      }
    }
  }
  
  private function appendAllow(array & $acl, array $privileges): ?bool {
    foreach ($privileges as $privilege) {
      if (! isset($acl[$privilege])) {
        $acl[$privilege] = self::ALLOW;
      }
    }
    
    return self::ALLOW;
  }
  
  private function appendDeny(array & $acl, array $privileges): ?bool {
    foreach ($privileges as $privilege) {
      if (isset($acl[$privilege])) {
        $acl[$privilege] = self::DENY;
      }
    }
    
    return self::DENY;
  }
  
  public function getAcl(): array {
    return $this->acl;
  }

}
