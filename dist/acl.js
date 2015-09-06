angular.module('ng-acl', []);
/**
 * @interface AclResourceInterface
 */
/**
 * Returns the string identifier of the Resource
 *
 * @function
 * @name AclResourceInterface#getResourceId
 * @returns {string}
 */

/**
 * Role provider interface, provides existing roles list
 *
 * @interface AclRoleInterface
 */
/**
 * Returns array of the Role string identifiers
 *
 * @function
 * @name AclRoleInterface#getRoles
 * @returns {Array<string>}
 */

/**
 * Returns true if and only if the assertion conditions are met
 *
 * This method is passed the ACL, Role, Resource, and privilege to which the authorization query applies. If the
 * $role, $resource, or $privilege parameters are null, it means that the query applies to all Roles, Resources, or
 * privileges, respectively.
 *
 * @callback AclAssertion
 * @param {AclRoleInterface|string} role
 * @param {AclResourceInterface|string} resource
 * @param {string} privilege
 */


/**
 * @ngdoc service
 * @name AclService
 * @description
 *    Provides a lightweight and flexible access control list (ACL) implementation for privileges management.
 *    In general, an application may utilize such ACL‘s to control access to certain protected objects by other requesting objects.
 */
angular.module('ng-acl').service('AclService', ["AclRegistryService", function (AclRegistryService) {
    'use strict';
    var self = this;

    self.TYPE_ALLOW = 'TYPE_ALLOW';
    self.TYPE_DENY  = 'TYPE_DENY';
    self.OP_ADD = 'OP_ADD';
    self.OP_REMOVE = 'OP_REMOVE';
    self.USER_IDENTITY_ROLE = 'ng-acl.role';

    var _userIdentity = null;
    var _roleRegistry = new AclRegistryService();// jshint ignore:line
    var _resources = {};
    var _rules = {
        allResources: {
            allRoles: {
                allPrivileges: {
                    type: self.TYPE_DENY,
                    assert: null
                },
                byPrivilegeId: {}
            },
            byRoleId: {}
        },
        byResourceId: {}
    };
    var _isAllowedResource = null;
    var _isAllowedRole = null;

    /**
     * @returns {(AclRoleInterface|null)}
     */
    this.getUserIdentity = function () {
        return _userIdentity;
    };

    /**
     * @param {AclRoleInterface} identity
     * @returns {AclService} Provides a fluent interface
     */
    this.setUserIdentity = function (identity) {
        if (!(identity instanceof Object) || typeof identity.getRoles !== 'function') {
            throw new Error('Incorrect user identity');
        }

        if (self.hasRole(self.USER_IDENTITY_ROLE)) {
            self.removeRole(self.USER_IDENTITY_ROLE);
        }

        self.addRole(self.USER_IDENTITY_ROLE, identity.getRoles());

        _userIdentity = identity;

        return self;
    };

    this.clearUserIdentity = function () {
        _userIdentity = null;
        self.removeRole(self.USER_IDENTITY_ROLE);

        return self;
    };

    /**
     * @param {(string|AclResourceInterface)} [resource=null]
     * @param {string} [privilege=null]
     * @returns {boolean}
     */
    this.can = function (resource, privilege) {
        resource = typeof resource === 'undefined' ? null : resource;
        privilege = typeof privilege === 'undefined' ? null : privilege;

        if (self.getUserIdentity() === null) {
            throw new Error('User identity is null');
        }

        return self.isAllowed(self.USER_IDENTITY_ROLE, resource, privilege);
    };

    /**
     * Adds an "allow" rule to the ACL
     *
     * @param {(string|Array)} [roles=null]
     * @param {(string|Array)} [resources=null]
     * @param {(string|Array)} [privileges=null]
     * @param {AclAssertion} assert
     * @return {AclService} Provides a fluent interface
     */
    this.allow = function (roles /*null*/, resources /*null*/, privileges /*null*/, assert /*null*/) {
        roles = typeof roles === 'undefined' ? null : roles;
        resources = typeof resources === 'undefined' ? null : resources;
        privileges = typeof privileges === 'undefined' ? null : privileges;
        assert = typeof assert === 'undefined' ? null : assert;

        return setRule(self.OP_ADD, self.TYPE_ALLOW, roles, resources, privileges, assert);
    };

    /**
     * Adds a "deny" rule to the ACL
     *
     * @param {(string|Array)} [roles=null]
     * @param {(string|Array)} [resources=null]
     * @param {(string|Array)} [privileges=null]
     * @param {AclAssertion} assert
     * @return {AclService} Provides a fluent interface
     */
    this.deny = function (roles /*null*/, resources /*null*/, privileges /*null*/, assert /*null*/) {
        roles = typeof roles === 'undefined' ? null : roles;
        resources = typeof resources === 'undefined' ? null : resources;
        privileges = typeof privileges === 'undefined' ? null : privileges;
        assert = typeof assert === 'undefined' ? null : assert;

        return setRule(self.OP_ADD, self.TYPE_DENY, roles, resources, privileges, assert);
    };

    /**
     * Removes an "allow" rule from the ACL
     *
     * @param {(string|Array)} [roles=null]
     * @param {(string|Array)} [resources=null]
     * @param {(string|Array)} [privileges=null]
     * @param {AclAssertion} assert
     * @return {AclService} Provides a fluent interface
     */
    this.removeAllow = function (roles, resources, privileges, assert) {
        roles = typeof roles === 'undefined' ? null : roles;
        resources = typeof resources === 'undefined' ? null : resources;
        privileges = typeof privileges === 'undefined' ? null : privileges;
        assert = typeof assert === 'undefined' ? null : assert;

        return setRule(self.OP_REMOVE, self.TYPE_ALLOW, roles, resources, privileges, assert);
    };

    /**
     * Removes an "deny" rule from the ACL
     *
     * @param {(string|Array)} [roles=null]
     * @param {(string|Array)} [resources=null]
     * @param {(string|Array)} [privileges=null]
     * @param {AclAssertion} assert
     * @return {AclService} Provides a fluent interface
     */
    this.removeDeny = function (roles, resources, privileges, assert) {
        roles = typeof roles === 'undefined' ? null : roles;
        resources = typeof resources === 'undefined' ? null : resources;
        privileges = typeof privileges === 'undefined' ? null : privileges;
        assert = typeof assert === 'undefined' ? null : assert;

        return setRule(self.OP_REMOVE, self.TYPE_DENY, roles, resources, privileges, assert);
    };

    /**
     * Returns true if and only if the Role has access to the Resource
     *
     * The $role and $resource parameters may be references to, or the string identifiers for,
     * an existing Resource and Role combination.
     *
     * If either $role or $resource is null, then the query applies to all Roles or all Resources,
     * respectively. Both may be null to query whether the ACL has a "blacklist" rule
     * (allow everything to all). By default, Zend\Permissions\Acl creates a "whitelist" rule (deny
     * everything to all), and this method would return false unless this default has
     * been overridden (i.e., by executing $acl->allow()).
     *
     * If a $privilege is not provided, then this method returns false if and only if the
     * Role is denied access to at least one privilege upon the Resource. In other words, this
     * method returns true if and only if the Role is allowed all privileges on the Resource.
     *
     * This method checks Role inheritance using a depth-first traversal of the Role registry.
     * The highest priority parent (i.e., the parent most recently added) is checked first,
     * and its respective parents are checked similarly before the lower-priority parents of
     * the Role are checked.
     *
     * @param  {string} [role=null]
     * @param  {string|AclResourceInterface} [resource=null]
     * @param  {string} [privilege=null]
     * @return {boolean}
     */
    this.isAllowed = function (role, resource, privilege) {
        role = typeof role === 'undefined' ? null : role;
        resource = typeof resource === 'undefined' ? null : resource;
        privilege = typeof privilege === 'undefined' ? null : privilege;
        var result, ruleTypeAllPrivileges;

        // reset role & resource to null
        _isAllowedRole = null;
        _isAllowedResource = null;

        if (role !== null) {
            _isAllowedRole = role;
            role = self.getRole(role);
        }
        if (resource !== null) {
            _isAllowedResource = resource;
            resource = self.getResource(resource);
        }

        if (privilege === null) {
            // query on all privileges
            do {
                // depth-first search on $role if it is not 'allRoles' pseudo-parent
                if (role !== null && (result = roleDFSAllPrivileges(role, resource, privilege)) !== null) {
                    return result;
                }

                // look for rule on 'allRoles' pseudo-parent
                var rules;
                if ((rules = getRules(resource, null)) !== null) {
                    for (privilege in rules.byPrivilegeId) {
                        if (self.TYPE_DENY === getRuleType(resource, null, privilege)) {
                            return false;
                        }
                    }
                    if (null !== (ruleTypeAllPrivileges = getRuleType(resource, null, null))) {
                        return self.TYPE_ALLOW === ruleTypeAllPrivileges;
                    }
                }

                // try next Resource
                resource = _resources[resource].parent;
            } while (true); // loop terminates at 'allResources' pseudo-parent
        } else {
            // query on one privilege
            do {
                // depth-first search on $role if it is not 'allRoles' pseudo-parent
                if (role !== null && null !== (result = roleDFSOnePrivilege(role, resource, privilege))) {
                    return result;
                }

                // look for rule on 'allRoles' pseudo-parent
                var ruleType;
                if (null !== (ruleType = getRuleType(resource, null, privilege))) {
                    return self.TYPE_ALLOW === ruleType;
                } else if (null !== (ruleTypeAllPrivileges = getRuleType(resource, null, null))) {
                    result = self.TYPE_ALLOW === ruleTypeAllPrivileges;
                    if (result || null === resource) {
                        return result;
                    }
                }

                // try next Resource
                resource = _resources[resource].parent;
            } while (true); // loop terminates at 'allResources' pseudo-parent
        }

    };

    /**
     * Adds a Resource having an identifier unique to the ACL
     *
     * The $parent parameter may be a reference to, or the string identifier for,
     * the existing Resource from which the newly added Resource will inherit.
     *
     * @param  {string} resource
     * @param  {string} [parent=null]
     * @return {AclService} Provides a fluent interface
     */
    this.addResource = function (resource, parent) {
        parent = typeof parent === 'undefined' ? null : parent;

        if (typeof resource !== 'string' || resource === '') {
            throw new Error('addResource() expects resource to be a not empty string');
        }

        var resourceId = resource;

        if (self.hasResource(resourceId)) {
            throw new Error("Resource id 'resourceId' already exists in the ACL");
        }

        if (parent !== null) {
            if (!self.hasResource(parent)) {
                throw new Error("Parent resource id not exists in the ACL");
            }

            _resources[parent].children.push(resourceId);
        }

        _resources[resourceId] = {
            id: resourceId,
            parent: parent,
            children: []
        };

        return self;
    };

    /**
     * Returns the identified Resource
     *
     * The $resource parameter can either be a Resource or a Resource identifier.
     *
     * @param  {(string|AclResourceInterface)} resource
     * @return {string}
     */
    this.getResource = function (resource)
    {
        if (!self.hasResource(resource)) {
            throw new Error("Resource '$resourceId' not found");
        }

        if (resource instanceof Object && typeof resource.getResourceId === 'function') {
            resource = resource.getResourceId();
        }

        return _resources[resource].id;
    };

    /**
     * @return {Array.<string>} of registered resources
     */
    this.getResources = function () {
        return Object.keys(_resources);
    };

    /**
     * Returns true if and only if the Resource exists in the ACL
     *
     * The $resource parameter can either be a Resource or a Resource identifier.
     *
     * @param {(string|AclResourceInterface)} resource
     * @return {boolean}
     */
    this.hasResource = function (resource) {
        if (resource instanceof Object && typeof resource.getResourceId === 'function') {
            resource = resource.getResourceId();
        }

        return _resources[resource] !== undefined;
    };

    /**
     * Returns true if and only if $resource inherits from $inherit
     *
     * Both parameters may be either a Resource or a Resource identifier. If
     * $onlyParent is true, then $resource must inherit directly from
     * $inherit in order to return true. By default, this method looks
     * through the entire inheritance tree to determine whether $resource
     * inherits from $inherit through its ancestor Resources.
     *
     * @param {(AclResourceInterface|string)} resource
     * @param {(AclResourceInterface|string)} inherit
     * @param {boolean} [onlyParent=false]
     * @return {boolean}
     */
    this.inheritsResource = function (resource, inherit, onlyParent) {
        resource = self.getResource(resource);
        inherit = self.getResource(inherit);

        var parentId = null;

        if (_resources[resource].parent !== null) {
            parentId = _resources[resource].parent;
            if (parentId === inherit) {
                return true;
            } else if (onlyParent) {
                return false;
            }
        } else {
            return false;
        }

        while (_resources[parentId].parent !== null) {
            parentId = _resources[parentId].parent;
            if (inherit === parentId) {
                return true;
            }
        }

        return false;
    };

    /**
     * Removes a Resource and all of its children
     *
     * The $resource parameter can either be a Resource or a Resource identifier.
     *
     * @param  {(string|AclResourceInterface)} resource
     * @return {AclService} Provides a fluent interface
     */
    this.removeResource = function (resource) {
        if (!self.hasResource(resource)) {
            throw new Error("Resource '$resourceId' not found");
        }

        if (resource instanceof Object && typeof resource.getResourceId === 'function') {
            resource = resource.getResourceId();
        }

        var resourcesRemoved = [resource];
        var resourceParent = _resources[resource].parent;
        if (resourceParent !== null) {
            _resources[resourceParent].children.splice(_resources[resourceParent].children.indexOf(resource), 1);
        }

        _resources[resource].children.forEach(function(child) {
            self.removeResource(child);
            resourcesRemoved.push(child);
        });

        resourcesRemoved.forEach(function(resourceRemoved) {
            for (var resourceCurrent in _rules.byResourceId) {
                if (resourceRemoved === resourceCurrent) {
                    delete _rules.byResourceId[resourceCurrent];
                }
            }
        });

        delete _resources[resource];

        return self;
    };

    /**
     * Removes all Resources
     *
     * @return {AclService} Provides a fluent interface
     */
    this.removeResourceAll = function () {
        for (var resourceId in _resources) {
            for (var resourceIdCurrent in _rules.byResourceId) {
                if (resourceId === resourceIdCurrent) {
                    delete _rules.byResourceId[resourceIdCurrent];
                }
            }
        }

        _resources = {};

        return self;
    };

    /**
     * Adds a Role having an identifier unique to the registry
     *
     * The $parents parameter may be a reference to, or the string identifier for,
     * a Role existing in the registry, or $parents may be passed as an array of
     * these - mixing string identifiers and objects is ok - to indicate the Roles
     * from which the newly added Role will directly inherit.
     *
     * In order to resolve potential ambiguities with conflicting rules inherited
     * from different parents, the most recently added parent takes precedence over
     * parents that were previously added. In other words, the first parent added
     * will have the least priority, and the last parent added will have the
     * highest priority.
     *
     * @param  {string} role
     * @param  {(string|Array.<string>)} [parents=null]
     * @return {AclService} Provides a fluent interface
     */
    this.addRole = function (role, parents) {
        parents = typeof parents === 'undefined' ? null : parents;

        if (typeof role !== 'string' || role === '') {
            throw new Error('addRole() expects role to be a not empty string');
        }

        _roleRegistry.add(role, parents);

        return self;
    };

    /**
     * Returns the identified Role
     *
     * The $role parameter can either be a Role or Role identifier.
     *
     * @param  {string} role
     * @return {string}
     */
    this.getRole = function (role) {
        return _roleRegistry.get(role);
    };

    /**
     * @return {Array.<string>} of registered roles
     */
    this.getRoles = function () {
        return Object.keys(_roleRegistry.getItems());
    };

    /**
     * Returns true if and only if the Role exists in the registry
     *
     * The $role parameter can either be a Role or a Role identifier.
     *
     * @param  {string} role
     * @return {boolean}
     */
    this.hasRole = function (role) {
        return _roleRegistry.has(role);
    };

    /**
     * Returns true if and only if $role inherits from $inherit
     *
     * Both parameters may be either a Role or a Role identifier. If
     * $onlyParents is true, then $role must inherit directly from
     * $inherit in order to return true. By default, this method looks
     * through the entire inheritance DAG to determine whether $role
     * inherits from $inherit through its ancestor Roles.
     *
     * @param  {string} role
     * @param  {string} inherit
     * @param  {boolean} [onlyParents=false]
     * @return {boolean}
     */
    this.inheritsRole = function (role, inherit, onlyParents) {
        onlyParents = typeof onlyParents === 'undefined' ? false : onlyParents;

        return _roleRegistry.inherits(role, inherit, onlyParents);
    };

    /**
     * Removes the Role from the registry
     *
     * The $role parameter can either be a Role or a Role identifier.
     *
     * @param  {string} role
     * @return {AclService} Provides a fluent interface
     */
    this.removeRole = function (role) {
        _roleRegistry.remove(role);

        if (_rules.allResources.byRoleId[role] !== undefined) {
            delete _rules.allResources.byRoleId[role];
        }

        for (var resourceCurrent in _rules.byResourceId) {
            var visitor = _rules.byResourceId[resourceCurrent];

            if (visitor.byRoleId !== undefined && visitor.byRoleId[role] !== undefined) {
                delete visitor.byRoleId[role];
            }
        }

        return self;
    };

    /**
     * Removes all Roles from the registry
     *
     * @return {AclService} Provides a fluent interface
     */
    this.removeRoleAll = function () {
        _roleRegistry.removeAll();

        for (var roleCurrent in _rules.allResources.byRoleId) {
            delete _rules.allResources.byRoleId[roleCurrent];
        }

        for (var resourceCurrent in _rules.byResourceId) {
            for (var roleIdCurrent in _rules.byResourceId[resourceCurrent].byRoleId) {
                delete _rules.byResourceId[resourceCurrent].byRoleId[roleIdCurrent];
            }
        }

        return self;
    };


    /**
     * Performs operations on ACL rules
     *
     * The $operation parameter may be either OP_ADD or OP_REMOVE, depending on whether the
     * user wants to add or remove a rule, respectively:
     *
     * OP_ADD specifics:
     *
     *      A rule is added that would allow one or more Roles access to [certain $privileges
     *      upon] the specified Resource(s).
     *
     * OP_REMOVE specifics:
     *
     *      The rule is removed only in the context of the given Roles, Resources, and privileges.
     *      Existing rules to which the remove operation does not apply would remain in the
     *      ACL.
     *
     * The $type parameter may be either TYPE_ALLOW or TYPE_DENY, depending on whether the
     * rule is intended to allow or deny permission, respectively.
     *
     * The $roles and $resources parameters may be references to, or the string identifiers for,
     * existing Resources/Roles, or they may be passed as arrays of these - mixing string identifiers
     * and objects is ok - to indicate the Resources and Roles to which the rule applies. If either
     * $roles or $resources is null, then the rule applies to all Roles or all Resources, respectively.
     * Both may be null in order to work with the default rule of the ACL.
     *
     * The $privileges parameter may be used to further specify that the rule applies only
     * to certain privileges upon the Resource(s) in question. This may be specified to be a single
     * privilege with a string, and multiple privileges may be specified as an array of strings.
     *
     * If $assert is provided, then its assert() method must return true in order for
     * the rule to apply. If $assert is provided with $roles, $resources, and $privileges all
     * equal to null, then a rule having a type of:
     *
     *      TYPE_ALLOW will imply a type of TYPE_DENY, and
     *
     *      TYPE_DENY will imply a type of TYPE_ALLOW
     *
     * when the rule's assertion fails. This is because the ACL needs to provide expected
     * behavior when an assertion upon the default ACL rule fails.
     *
     * @param  {string} operation
     * @param  {string} type
     * @param  {string|Array.<string>} [roles=null]
     * @param  {string|Array.<string>} [resources=null]
     * @param  {string|Array.<string>} [privileges=null]
     * @param  {function} [assert=null]
     * @return {AclService} Provides a fluent interface
     */
    function setRule (
        operation,
        type,
        roles,
        resources,
        privileges,
        assert
    ) {
        roles = typeof roles === 'undefined' ? null : roles;
        resources = typeof resources === 'undefined' ? null : resources;
        privileges = typeof privileges === 'undefined' ? null : privileges;
        assert = typeof assert === 'undefined' ? null : assert;

        // ensure that the rule type is valid; normalize input to uppercase
        type = type.toUpperCase();
        if (self.TYPE_ALLOW !== type && self.TYPE_DENY !== type) {
            throw new Error('Unsupported rule type');
        }

        // ensure that all specified Roles exist; normalize input to array of Role objects or null
        if (!Array.isArray(roles)) {
            roles = [roles];
        } else if (0 === roles.length) {
            roles = [null];
        }
        var rolesTemp = roles;
        roles = [];
        rolesTemp.forEach(function (role) {
            if (role !== null) {
                roles.push(self.getRole(role));
            } else {
                roles.push(null);
            }
        });

        // ensure that all specified Resources exist; normalize input to array of Resource objects or null
        if (!Array.isArray(resources)) {
            if (resources === null && Object.keys(_resources).length > 0) {
                resources = Object.keys(_resources);
                // Passing a null resource; make sure "global" permission is also set!
                if (resources.indexOf(null) === -1) {
                    resources.unshift(null);
                }
            } else {
                resources = [resources];
            }
        } else if (resources.length === 0) {
            resources = [null];
        }
        var resourcesTemp = resources;
        resources = [];
        resourcesTemp.forEach(function (resource) {
            if (resource !== null) {
                resource = self.getResource(resource);

                var children = getChildResources(resource);
                resources = resources.concat(children);
                resources.push(resource);
            } else {
                resources.push(null);
            }
        });

        // normalize privileges to array
        if (privileges === null ) {
            privileges = [];
        } else if (!Array.isArray(privileges)) {
            privileges = [privileges];
        }

        switch (operation) {
            // add to the rules
            case self.OP_ADD:
                resources.forEach(function (resource) {
                    roles.forEach(function (role) {
                        var rules = getRules(resource, role, true);
                        if (privileges.length === 0) {
                            set(rules, 'allPrivileges.type', type);
                            set(rules, 'allPrivileges.assert', assert);
                            if (rules.byPrivilegeId === undefined) {
                                rules.byPrivilegeId = {};
                            }
                        } else {
                            privileges.forEach(function (privilege) {
                                set(rules, 'byPrivilegeId.' + privilege + '.type', type);
                                set(rules, 'byPrivilegeId.' + privilege + '.assert', assert);
                            });
                        }
                    });
                });
                break;

            // remove from the rules
            case self.OP_REMOVE:
                resources.forEach(function (resource) {
                    roles.forEach(function (role) {
                        var rules = getRules(resource, role);
                        if (rules === null) {
                            return;
                        }

                        if (privileges.length === 0) {
                            if (resource === null && role === null) {
                                if (rules.allPrivileges.type === type) {
                                    set(rules, 'allPrivileges.type', self.TYPE_DENY);
                                    set(rules, 'allPrivileges.assert', null);
                                    rules.byPrivilegeId = {};
                                }
                                return;
                            }

                            if (rules.allPrivileges !== undefined && rules.allPrivileges.type !== undefined && rules.allPrivileges.type === type) {
                                delete rules.allPrivileges;
                            }
                        } else {
                            privileges.forEach(function (privilege) {
                                if (rules.byPrivilegeId !== undefined && rules.byPrivilegeId[privilege] !== undefined &&
                                    rules.byPrivilegeId[privilege].type === type
                                ) {
                                    delete rules.byPrivilegeId[privilege];
                                }
                            });
                        }
                    });
                });
                break;

            default:
                throw new Error('Unsupported operation');
        }

        return self;
    }

    /**
     * Returns the rules associated with a Resource and a Role, or null if no such rules exist
     *
     * If either $resource or $role is null, this means that the rules returned are for all Resources or all Roles,
     * respectively. Both can be null to return the default rule set for all Resources and all Roles.
     *
     * If the $create parameter is true, then a rule set is first created and then returned to the caller.
     *
     * @param {string} [resource=null]
     * @param {string} [role=null]
     * @param {boolean} [create=false]
     * @return {Object|null}
     */
    function getRules (resource, role, create) {
        resource = typeof resource === 'undefined' ? null : resource;
        role = typeof role === 'undefined' ? null : role;
        create = typeof create === 'undefined' ? false : create;

        var visitor;

        // follow $resource
        do {
            if (resource === null) {
                visitor = _rules.allResources;
                break;
            }
            //var resourceId = resource.getResourceId();
            var resourceId = resource;
            if (_rules.byResourceId[resourceId] === undefined) {
                if (!create) {
                    return null;
                }
                _rules.byResourceId[resourceId] = {};
            }
            visitor = _rules.byResourceId[resourceId];
        } while (false);

        // follow $role
        if (role === null) {
            if (visitor.allRoles === undefined) {
                if (!create) {
                    return null;
                }
                set(visitor, 'allRoles.byPrivilegeId', {});
            }
            return visitor.allRoles;
        }
        //var roleId = role.getRoleId();
        var roleId = role;
        if (visitor.byRoleId === undefined || visitor.byRoleId[roleId] === undefined) {
            if (!create) {
                return null;
            }
            set(visitor, 'byRoleId.' + roleId + '.byPrivilegeId', {});
        }
        return visitor.byRoleId[roleId];
    }

    /**
     * Performs a depth-first search of the Role DAG, starting at $role, in order to find a rule
     * allowing/denying $role access to all privileges upon $resource
     *
     * This method returns true if a rule is found and allows access. If a rule exists and denies access,
     * then this method returns false. If no applicable rule is found, then this method returns null.
     *
     * @param {string} role
     * @param {string} [resource=null]
     * @return {(boolean|null)}
     */
    function roleDFSAllPrivileges(role, resource){
        var dfs = {
            visited: {},
            stack: []
        };
        var result;

        if (null !== (result = roleDFSVisitAllPrivileges(role, resource, dfs))) {
            return result;
        }

        // This comment is needed due to a strange php-cs-fixer bug
        while (null !== (role = array_pop(dfs.stack))) {
            if (dfs.visited[role] === undefined) {
                if (null !== (result = roleDFSVisitAllPrivileges(role, resource, dfs))) {
                    return result;
                }
            }
        }

        return null;
    }

    /**
     * Visits an $role in order to look for a rule allowing/denying $role access to all privileges upon $resource
     *
     * This method returns true if a rule is found and allows access. If a rule exists and denies access,
     * then this method returns false. If no applicable rule is found, then this method returns null.
     *
     * This method is used by the internal depth-first search algorithm and may modify the DFS data structure.
     *
     * @param {string} role
     * @param {string} [resource=null]
     * @param {Object} [dfs=null]
     * @return {(boolean|null)}
     */
    function roleDFSVisitAllPrivileges(role, resource, dfs) {
        resource = typeof resource === 'undefined' ? null : resource;
        dfs = typeof dfs === 'undefined' ? null : dfs;

        if (dfs === null) {
            throw new Error('$dfs parameter may not be null');
        }

        var rules;
        if ((rules = getRules(resource, role)) !== null) {
            for (var privilege in rules.byPrivilegeId) {
                var rule = rules.byPrivilegeId[privilege];

                if (self.TYPE_DENY === getRuleType(resource, role, privilege)) {
                    return false;
                }
            }
            var ruleTypeAllPrivileges;
            if (null !== (ruleTypeAllPrivileges = getRuleType(resource, role, null))) {
                return self.TYPE_ALLOW === ruleTypeAllPrivileges;
            }
        }

        dfs.visited[role] = true;
        _roleRegistry.getParents(role).forEach(function (roleParent) {
            dfs.stack.push(roleParent);
        });

        return null;
    }

    /**
     * Performs a depth-first search of the Role DAG, starting at $role, in order to find a rule
     * allowing/denying $role access to a $privilege upon $resource
     *
     * This method returns true if a rule is found and allows access. If a rule exists and denies access,
     * then this method returns false. If no applicable rule is found, then this method returns null.
     *
     * @param {string} role
     * @param {string} [resource=null]
     * @param {string} [privilege=null]
     * @return {(boolean|null)}
     */
    function roleDFSOnePrivilege(role, resource, privilege) {
        resource = typeof resource === 'undefined' ? null : resource;
        privilege = typeof privilege === 'undefined' ? null : privilege;

        if (null === privilege) {
            throw new Error('$privilege parameter may not be null');
        }

        var dfs = {
            visited: {},
            stack: []
        };

        var result;

        if (null !== (result = roleDFSVisitOnePrivilege(role, resource, privilege, dfs))) {
            return result;
        }

        // This comment is needed due to a strange php-cs-fixer bug
        while (null !== (role = array_pop(dfs.stack))) {
            if (dfs.visited[role] === undefined) {
                if (null !== (result = roleDFSVisitOnePrivilege(role, resource, privilege, dfs))) {
                    return result;
                }
            }
        }

        return null;
    }

    /**
     * Visits an $role in order to look for a rule allowing/denying $role access to a $privilege upon $resource
     *
     * This method returns true if a rule is found and allows access. If a rule exists and denies access,
     * then this method returns false. If no applicable rule is found, then this method returns null.
     *
     * This method is used by the internal depth-first search algorithm and may modify the DFS data structure.
     *
     * @param {string} role
     * @param {string} [resource=null]
     * @param {string} [privilege=null]
     * @param {Object} [dfs=null]
     * @return {(boolean|null)}
     */
    function roleDFSVisitOnePrivilege(role, resource, privilege, dfs) {
        resource = typeof resource === 'undefined' ? null : resource;
        privilege = typeof privilege === 'undefined' ? null : privilege;
        dfs = typeof dfs === 'undefined' ? null : dfs;

        if (privilege === null) {
            throw new Error('$privilege parameter may not be null');
        }

        if (dfs === null) {
            throw new Error('$dfs parameter may not be null');
        }

        var ruleTypeOnePrivilege, ruleTypeAllPrivileges;
        if (null !== (ruleTypeOnePrivilege = getRuleType(resource, role, privilege))) {
            return self.TYPE_ALLOW === ruleTypeOnePrivilege;
        } else if (null !== (ruleTypeAllPrivileges = getRuleType(resource, role, null))) {
            return self.TYPE_ALLOW === ruleTypeAllPrivileges;
        }

        dfs.visited[role] = true;
        _roleRegistry.getParents(role).forEach(function (roleParent) {
            dfs.stack.push(roleParent);
        });

        return null;
    }

    /**
     * Returns the rule type associated with the specified Resource, Role, and privilege
     * combination.
     *
     * If a rule does not exist or its attached assertion fails, which means that
     * the rule is not applicable, then this method returns null. Otherwise, the
     * rule type applies and is returned as either TYPE_ALLOW or TYPE_DENY.
     *
     * If $resource or $role is null, then this means that the rule must apply to
     * all Resources or Roles, respectively.
     *
     * If $privilege is null, then the rule must apply to all privileges.
     *
     * If all three parameters are null, then the default ACL rule type is returned,
     * based on whether its assertion method passes.
     *
     * @param  {null|string} [resource=null]
     * @param  {null|string} [role=null]
     * @param  {null|string} [privilege=null]
     * @return {(string|null)}
     */
    function getRuleType(resource, role, privilege) {
        resource = typeof resource === 'undefined' ? null : resource;
        role = typeof role === 'undefined' ? null : role;
        privilege = typeof privilege === 'undefined' ? null : privilege;


        // get the rules for the $resource and $role
        var rules = getRules(resource, role);
        if (rules === null) {
            return null;
        }

        var rule;

        // follow $privilege
        if (privilege === null) {
            if (rules.allPrivileges !== undefined) {
                rule = rules.allPrivileges;
            } else {
                return null;
            }
        } else if (rules.byPrivilegeId === undefined || rules.byPrivilegeId[privilege] === undefined) {
            return null;
        } else {
            rule = rules.byPrivilegeId[privilege];
        }

        // check assertion first
        var assertionValue = null;
        if (rule.assert !== null) {
            var assertion = rule.assert;
            assertionValue = assertion.call(
                self,
                _isAllowedRole === self.USER_IDENTITY_ROLE && self.getUserIdentity() !== null ? self.getUserIdentity() : role,
                _isAllowedResource !== null ? _isAllowedResource : resource,
                privilege
            );
        }

        if (rule.assert === null || assertionValue === true) {
            return rule.type;
        } else if (null !== resource || null !== role || null !== privilege) {
            return null;
        } else if (self.TYPE_ALLOW === rule.type) {
            return self.TYPE_DENY;
        }

        return self.TYPE_ALLOW;
    }

    /**
     * Returns all child resources from the given resource.
     *
     * @param {string} resource
     * @return []
     */
    function getChildResources(resource){
        var result = [];

        var children = _resources[resource].children;
        children.forEach(function (child) {
            var child_return = getChildResources(child);
            child_return.push(child);
            result = result.concat(child_return);
        });

        return result;
    }

    function set(schema, path, value) {
        var pList = path.split('.');
        var len = pList.length;

        for(var i = 0; i < len - 1; i++) {
            var elem = pList[i];
            if(!schema[elem]) {
                schema[elem] = {};
            }
            schema = schema[elem];
        }

        schema[pList[len - 1]] = value;
    }

    function array_pop(inputArr) {
        var key = '',
            lastKey = '';

        if (inputArr.hasOwnProperty('length')) {
            // Indexed
            if (!inputArr.length) {
                // Done popping, are we?
                return null;
            }
            return inputArr.pop();
        } else {
            // Associative
            for (key in inputArr) {
                if (inputArr.hasOwnProperty(key)) {
                    lastKey = key;
                }
            }
            if (lastKey) {
                var tmp = inputArr[lastKey];
                delete(inputArr[lastKey]);
                return tmp;
            } else {
                return null;
            }
        }
    }
}]);
/**
 * @ngdoc service
 * @name AclRegistryService
 * @description AclRegistryService factory
 */
angular.module('ng-acl').factory('AclRegistryService', function () {
    'use strict';

    /**
     * @ngdoc method
     * @constructs AclRegistryService
     * @description Initializes a new ACL role registry
     */
    var AclRegistryService = function () {
        var self = this;
        var _storage = {};

        this.add = function (item, parents /*null*/) {
            parents = typeof parents === 'undefined' ? null : parents;

            if (self.has(item)) {
                throw new Error('Item "' + item + '" already exists in the registry');
            }

            var itemParents = [];

            if (parents !== null) {
                if (!Array.isArray(parents)) {
                    parents = [parents];
                }

                parents.forEach(function (parent) {
                    if (!self.has(parent)) {
                        throw new Error('Parent role "' + parent + '" for "' + item + '" not exists in the registry');
                    }

                    itemParents.push(parent);
                    _storage[parent].children.push(item);
                });
            }

            _storage[item] = {
                id: item,
                parents: itemParents,
                children: []
            };

            return self;
        };

        this.get = function (item) {
            if (!self.has(item)) {
                throw new Error('Item "' + item + '" not exists in the registry');
            }

            return item;
        };

        this.has = function (item) {
            return _storage[item] !== undefined;
        };

        this.getParents = function (item) {
            if (!self.has(item)) {
                throw new Error('Item "' + item + '" not exists in the registry');
            }

            return _storage[item].parents;
        };

        this.inherits = function (item, inherit, onlyParents /*false*/) {
            onlyParents = typeof onlyParents === 'undefined' ? false : onlyParents;

            if (!self.has(item) || !self.has(inherit)) {
                throw new Error('Items not exists in the registry');
            }

            var inherits = _storage[item].parents.indexOf(inherit) !== -1;

            if (inherits || onlyParents) {
                return inherits;
            }

            for (var i = 0; i < _storage[item].parents.length; i++) {
                var parent = _storage[item].parents[i];

                if (self.inherits(parent, inherit)) {
                    return true;
                }
            }

            return false;
        };

        this.remove = function (item) {
            if (!self.has(item)) {
                throw new Error('Item "' + item + '" not exists in the registry');
            }

            _storage[item].children.forEach(function (child) {
                var index = _storage[child].parents.indexOf(item);
                if (index !== -1) {
                    _storage[child].parents.splice(index, 1);
                }
            });
            _storage[item].parents.forEach(function (parent) {
                var index = _storage[parent].children.indexOf(item);
                if (index !== -1) {
                    _storage[parent].children.splice(index, 1);
                }
            });

            delete _storage[item];

            return self;
        };

        this.removeAll = function () {
            _storage = {};

            return self;
        };

        this.getItems = function () {
            return angular.copy(_storage);
        };


        return this;
    };

    return AclRegistryService;
});