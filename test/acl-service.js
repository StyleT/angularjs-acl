'use strict';

describe('ncAclService', function () {
    /** @type {AclService} */
    var AclService;

    var userIdentityStub = {
        roles: null,
        getRoles: function () {
            return this.roles;
        }
    };
    var resourceStub = {
        name: 'Dezmond',
        resourceId: 'test',
        getResourceId: function () {
            return this.resourceId;
        }
    };

    beforeEach(module('stylet.acl'));

    beforeEach(inject(function (_AclService_) {
        AclService = _AclService_;
    }));

    beforeEach(function () {
        userIdentityStub.roles = ['user', 'test'];
        resourceStub.resourceId = 'test';
    });

    describe('UserIdentity management', function () {

        it('should return null by default', function () {
            expect(AclService.getUserIdentity()).toEqual(null);
        });

        it('should set valid user identity', function () {
            userIdentityStub.roles = [];
            AclService.setUserIdentity(userIdentityStub);
            expect(AclService.getUserIdentity()).toEqual(userIdentityStub);
        });

        it('should create inherited role for user identity or replace old one if it exists', function () {
            AclService.addRole('Guest');
            AclService.addRole('User');
            AclService.addRole('Admin');

            userIdentityStub.roles = ['User', 'Guest'];
            AclService.setUserIdentity(userIdentityStub);

            expect(AclService.hasRole(AclService.USER_IDENTITY_ROLE)).toBeTruthy();
            expect(AclService.inheritsRole(AclService.USER_IDENTITY_ROLE, 'Guest')).toBeTruthy();
            expect(AclService.inheritsRole(AclService.USER_IDENTITY_ROLE, 'User')).toBeTruthy();
            expect(AclService.inheritsRole(AclService.USER_IDENTITY_ROLE, 'Admin')).toBeFalsy();

            userIdentityStub.roles = ['Admin'];
            AclService.setUserIdentity(userIdentityStub);
            expect(AclService.inheritsRole(AclService.USER_IDENTITY_ROLE, 'Admin')).toBeTruthy();
            expect(AclService.inheritsRole(AclService.USER_IDENTITY_ROLE, 'Guest')).toBeFalsy();
            expect(AclService.inheritsRole(AclService.USER_IDENTITY_ROLE, 'User')).toBeFalsy();
        });

        it('should throw error with invalid user identity', function () {
            expect(function() {
                AclService.setUserIdentity({});
            }).toThrow();
        });

        it('should return AclService object', function () {
            userIdentityStub.roles = [];
            expect(AclService.setUserIdentity(userIdentityStub)).toEqual(AclService);
        });

        it('should clean previously specified entity', function () {
            userIdentityStub.roles = [];
            AclService.setUserIdentity(userIdentityStub);
            expect(AclService.getUserIdentity()).toEqual(userIdentityStub);

            AclService.clearUserIdentity();
            expect(AclService.getUserIdentity()).toEqual(null);
        });

    });

    describe('Role management', function () {

        it('ensures that getRoles() method works as expected', function () {
            expect(AclService.getRoles()).toEqual([]);

            AclService
                .addRole('guest')
                .addRole('staff', 'guest')
                .addRole('editor', 'staff')
                .addRole('administrator');

            expect(AclService.getRoles()).toEqual(['guest', 'staff', 'editor', 'administrator']);
        });

        it('basic role adding/removal', function () {
            AclService.addRole('User');
            AclService.addRole('Manager', 'User');
            AclService.addRole('God', 'Manager');

            expect(AclService.hasRole('Manager')).toBeTruthy();

            AclService.removeRole('Manager');

            expect(AclService.hasRole('Manager')).toBeFalsy();
            expect(AclService.hasRole('God')).toBeFalsy();
        });

        it('should throw Exception during removal of unexisted role', function () {
            expect(function() {
                AclService.removeRole('unexisted');
            }).toThrow();
        });

        it('ensures that removal of all Roles works', function () {
            AclService.addRole('Guest');
            expect(AclService.hasRole('Guest')).toBeTruthy();

            AclService.removeRoleAll();
            expect(AclService.hasRole('Guest')).toBeFalsy();
        });

        it('ensures that removal of all Roles results in Role-specific rules being removed', function () {
            AclService.addRole('Guest').allow('Guest');
            expect(AclService.isAllowed('Guest')).toBeTruthy();

            AclService.removeRoleAll();

            AclService.addRole('Guest');
            expect(AclService.isAllowed('Guest')).toBeFalsy();
        });

    });

    describe('Resource management', function () {

        it('ensures that getResources() method works as expected', function () {
            expect(AclService.getResources()).toEqual([]);

            AclService
                .addResource('Animal')
                .addResource('Cat', 'Animal')
                .addResource('Kitty', 'Cat')
                .addResource('Rock');

            expect(AclService.getResources()).toEqual(['Animal', 'Cat', 'Kitty', 'Rock']);
        });

        it('should remove single resource', function () {
            AclService
                .addResource('Animal')
                .addResource('Cat', 'Animal')
                .addResource('Kitty', 'Cat');

            expect(AclService.hasResource('Cat')).toBeTruthy();

            AclService.removeResource('Cat');

            expect(AclService.hasResource('Cat')).toBeFalsy();
            expect(AclService.hasResource('Kitty')).toBeFalsy();
        });

        it('should throw Exception during removal of unexisted resource', function () {
            expect(function() {
                AclService.removeResource('unexisted');
            }).toThrow();
        });

        it('ensures that an exception is thrown when a non-existent resource is specified to each parameter of inherits()', function () {
            AclService.addResource('Animal');

            expect(function() {
                AclService.inheritsResource('nonexistent', 'Animal');
            }).toThrow();

            expect(function() {
                AclService.inheritsResource('Animal', 'nonexistent');
            }).toThrow();
        });

        it('tests basic resource inheritance', function () {
            AclService
                .addResource('city')
                .addResource('building', 'city')
                .addResource('room', 'building');

            expect(AclService.inheritsResource('building', 'city', true)).toBeTruthy();
            expect(AclService.inheritsResource('room', 'building', true)).toBeTruthy();
            expect(AclService.inheritsResource('room', 'city')).toBeTruthy();
            expect(AclService.inheritsResource('room', 'city', true)).toBeFalsy();
            expect(AclService.inheritsResource('city', 'building')).toBeFalsy();
            expect(AclService.inheritsResource('building', 'room')).toBeFalsy();
            expect(AclService.inheritsResource('city', 'room')).toBeFalsy();

            AclService.removeResource('building');
            expect(AclService.hasResource('room')).toBeFalsy();
        });

        it('ensures that removal of all resources works', function () {
            AclService
                .addResource('Animal')
                .addResource('Fish')
                .removeResourceAll();

            expect(AclService.hasResource('Animal')).toBeFalsy();
            expect(AclService.hasResource('Fish')).toBeFalsy();
        });

        it('ensures that removal of all resources results in Resource-specific rules being removed', function () {
            AclService
                .addResource('Animal')
                .allow(null, 'Animal');

            expect(AclService.isAllowed(null, 'Animal')).toBeTruthy();

            AclService.removeResourceAll().addResource('Animal');

            expect(AclService.isAllowed(null, 'Animal')).toBeFalsy();
        });

    });

    describe('can()', function () {

        it('should work with user with multiple roles', function () {
            AclService.addRole('User');
            AclService.addRole('Manager');
            AclService.addResource('Posts');
            AclService.allow('Manager', 'Posts');

            userIdentityStub.roles = ['User', 'Manager'];
            AclService.setUserIdentity(userIdentityStub);

            expect(AclService.can('Posts')).toBeTruthy();
        });

        it('should work with assertions', function () {
            AclService.addRole('User');
            AclService.addResource('Posts');
            AclService.allow('User', 'Posts', null, function (role, resource, privilege) {
                return role.name === 'Dezmond' && resource === 'Posts';
            });

            userIdentityStub.roles = ['User'];
            userIdentityStub.name = 'Dezmond';
            AclService.setUserIdentity(userIdentityStub);

            expect(AclService.can('Posts')).toBeTruthy();
        });

    });

    describe('isAllowed()', function () {

        it('should work with role & resource inheritance', function () {
            AclService.addRole('user');
            AclService.addRole('admin', 'user');
            AclService.addRole('manager', 'user');

            AclService.addResource('User');
            AclService.addResource('Manager', 'User');
            AclService.addResource('Admin', 'User');

            AclService.allow('user', 'User', 'edit');
            AclService.allow('manager', 'Manager', 'view');

            expect(AclService.isAllowed('admin', 'Admin', 'edit')).toBeTruthy();
            expect(AclService.isAllowed('user', 'Admin', 'edit')).toBeTruthy();
            expect(AclService.isAllowed('admin', 'User', 'edit')).toBeTruthy();
            expect(AclService.isAllowed('user', 'User', 'edit')).toBeTruthy();

            expect(AclService.isAllowed('manager', 'Manager', 'view')).toBeTruthy();
            expect(AclService.isAllowed('user', 'Manager', 'view')).toBeFalsy();
            expect(AclService.isAllowed('user', 'Manager', 'edit')).toBeTruthy();
            expect(AclService.isAllowed('manager', 'User', 'view')).toBeFalsy();

            expect(AclService.isAllowed('admin', 'Admin')).toBeFalsy();
        });

        it('privilege test', function () {
            AclService.addRole('user');
            AclService.addResource('User');
            AclService.allow('user', 'User');

            expect(AclService.isAllowed('user', 'User')).toBeTruthy();
            expect(AclService.isAllowed('user', 'User', 'anything')).toBeTruthy();
        });

        it('should work with ncAclResourceInterface', function () {
            AclService.addRole('user');
            AclService.addResource('test');
            AclService.allow('user', 'test', null, function (role, resource, privilege) {
                return role === 'user' && resource.name === 'Dezmond';
            });

            expect(AclService.isAllowed('user', resourceStub)).toBeTruthy();
            expect(AclService.isAllowed('user', resourceStub, 'anything')).toBeTruthy();
        });

    });

    describe('allow()', function () {

        it('Should work with one role no privilege', function () {
            AclService.addRole('user');
            userIdentityStub.roles = ['user'];
            AclService.setUserIdentity(userIdentityStub);
            AclService.addResource('Post');
            AclService.addResource('Comment');
            AclService.allow('user', 'Post');

            expect(AclService.can('Post')).toBeTruthy();
            expect(AclService.can('Post', 'view')).toBeTruthy();
            expect(AclService.can('Comment')).toBeFalsy();
            expect(AclService.can('Comment', 'view')).toBeFalsy();
        });

        it('Should work with one role & privilege', function () {
            AclService.addRole('user');
            userIdentityStub.roles = ['user'];
            AclService.setUserIdentity(userIdentityStub);
            AclService.addResource('Post');
            AclService.allow('user', 'Post', 'edit');

            expect(AclService.can('Post', 'edit')).toBeTruthy();
            expect(AclService.can('Post', 'view')).toBeFalsy();
            expect(AclService.can('Post')).toBeFalsy();
        });

        it('Should work with multiple roles', function () {
            AclService.addRole('user');
            AclService.addRole('commenter');

            userIdentityStub.roles = ['user', 'commenter'];
            AclService.setUserIdentity(userIdentityStub);

            AclService.addResource('Post');
            AclService.addResource('Comment');

            AclService.allow('user', 'Post');
            AclService.allow('commenter', 'Comment');

            expect(AclService.can('Post')).toBeTruthy();
            expect(AclService.can('Comment')).toBeTruthy();
        });

    });

    describe('removeAllow()', function () {

        it('basic rule removal works', function () {
            AclService.allow(null, null, ['privilege1', 'privilege2']);
            expect(AclService.isAllowed()).toBeFalsy();
            expect(AclService.isAllowed(null, null, 'privilege1')).toBeTruthy();
            expect(AclService.isAllowed(null, null, 'privilege2')).toBeTruthy();
            AclService.removeAllow(null, null, ['privilege1']);
            expect(AclService.isAllowed(null, null, 'privilege1')).toBeFalsy();
            expect(AclService.isAllowed(null, null, 'privilege2')).toBeTruthy();
        });

        it('default allow removal', function () {
            AclService.allow();
            expect(AclService.isAllowed()).toBeTruthy();
            AclService.removeAllow();
            expect(AclService.isAllowed()).toBeFalsy();
        });
    });

    describe('removeDeny()', function () {
        it('Ensures that removing non-existent default deny rule does nothing', function () {
            AclService.allow().removeDeny();
            expect(AclService.isAllowed()).toBeTruthy();
        });
        it('Ensures that removing the default deny rule results in default deny rule', function () {
            expect(AclService.isAllowed()).toBeFalsy();
            AclService.removeDeny();
            expect(AclService.isAllowed()).toBeFalsy();
        });
    });
});