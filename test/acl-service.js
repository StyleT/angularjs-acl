'use strict';

describe('ncAclService', function () {
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

    describe('get/set UserIdentity', function () {

        it('should throw error with empty entity', function () {
            expect(AclService.getUserIdentity).toThrow();
        });

        it('should return valid entity', function () {
            AclService.setUserIdentity(userIdentityStub);
            expect(AclService.getUserIdentity).not.toThrow();
        });

        it('should return AclService object', function () {
            expect(AclService.setUserIdentity(userIdentityStub)).toEqual(AclService);
        });

    });

    describe('Resource management', function () {

        it('should remove single resource', function () {
            AclService.addResource('User');
            AclService.addResource('Manager', 'User');
            AclService.addResource('God', 'Manager');

            expect(AclService.hasResource('Manager')).toBeTruthy();

            AclService.removeResource('Manager');

            expect(AclService.hasResource('Manager')).toBeFalsy();
            expect(AclService.hasResource('God')).toBeFalsy();
        });

        it('should throw Exception during removal of unexisted resource', function () {
            expect(function() {
                AclService.removeResource('unexisted');
            }).toThrow();
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