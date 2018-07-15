<?php
declare(strict_types=1);

/**
 * This file is a part of the Simple Static ACL library.
 * Copyright (c) 2018 Nikolas Lada.
 * @author Nikolas Lada <nikolas.lada@gmail.com>
 */

namespace NikolasLada\SimpleStaticAcl;

class AclMutable {

  const
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
  
  
  public function addAccessType(string $accessType, ?string $parent): void {
    $this->checkItem($accessType, $this->accessTypes);
    $this->accessTypes[$accessType] = $parent;
  }
  
  public function addRole(string $role, ?string $parent): void {
    $this->checkItem($role, $this->roles);
    $this->roles[$role] = $parent;
  }
  
  public function addResource(string $resource, ?string $parent): void {
    $this->checkItem($resource, $this->resources);
    $this->resources[$resource] = $parent;
  }
  
  private function checkItem(string $item, array $itemList): void {
    if (in_array($item, $itemList, true)) {
      throw new \DomainException("The value of first parameter $item is already added.");
    }
  }

  public function allow(array $accessTypes, array $roles, array $resources, array $privileges): void {
    $this->setRights($accessTypes, $roles, $resources, $privileges, self::ALLOW);
  }
  
  public function deny(array $accessTypes, array $roles, array $resources, array $privileges): void {
    $this->setRights($accessTypes, $roles, $resources, $privileges, self::DENY);
  }
  
  public function getAcl(): array {
    return $this->acl;
  }
  
  /**
   * Non-public methods.
   */
  
  private function setRights(array $accessTypes, array $roles, array $resources, array $privileges, ?bool $status): void {
    $accessTypeList = $this->getItemList($accessTypes, $this->accessTypes);
    $roleList = $this->getItemList($roles, $this->roles);
    $resourceList = $this->getItemList($resources, $this->resources);
    
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
  
  private function getItemList(array $codeList, array $resource): array {
    $list = [];
    foreach ($codeList as $code) {
      if (\is_null($code)) {
        $list = array_keys($resource);
        break;
      } else {
        $list = $this->getItemWithDescendants($code, $resource, $list);
      }

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

  private function appendToAcl(array & $acl, array $path, ?bool $status): bool {
    $current = current($path);
    
    if (count($path) > 1) {
      if (! isset( $acl[$current] ) ) {
        $acl[$current] = [];
      }

      array_shift($path);
      return $this->appendToAcl($acl[$current], $path, $status);
    } else {
      if ($status === self::ALLOW) {
        $this->appendAllow($acl, $current);
      } else {
        $this->appendDeny($acl, $current);
      }
      
      return true;
    }
  }
  
  private function appendAllow(array & $acl, array $privileges): void {
    foreach ($privileges as $privilege) {
      if ($privilege === AclHandler::ALL) {
        $this->unsetPrivileges($acl);
        $acl[AclHandler::ALL] = self::ALLOW;
        break;
      }
      
      if (! isset($acl[$privilege])) {
        $acl[$privilege] = self::ALLOW;
      }
    }
  }
  
  private function appendDeny(array & $acl, array $privileges): void {
    foreach ($privileges as $privilege) {
      if ($privilege === AclHandler::ALL) {
        $this->unsetPrivileges($acl);
        $acl[AclHandler::ALL] = self::DENY;
        break;
      }
      
      if (isset($acl[$privilege])) {
        $acl[$privilege] = self::DENY;
      }
    }
  }
  
  private function unsetPrivileges(array & $acl): void {
    foreach ($acl as $k => $v) {
      unset($acl[$k]);
    }
  }

}
