'use strict';

describe('AclRegistryService', function () {
    /** @type {AclRegistryService} */
    var AclRegistryService;

    beforeEach(module('ng-acl'));

    beforeEach(inject(function (_AclRegistryService_) {
        AclRegistryService = new _AclRegistryService_();
    }));

    it('tests basic Role inheritance', function () {
        AclRegistryService
            .add('guest')
            .add('member', 'guest')
            .add('editor', 'member');

        expect(AclRegistryService.getParents('guest')).toEqual([]);

        var roleMemberParents = AclRegistryService.getParents('member');
        expect(roleMemberParents.length).toEqual(1);
        expect(roleMemberParents).toEqual(jasmine.arrayContaining(['guest']));

        var roleEditorParents = AclRegistryService.getParents('editor');
        expect(roleEditorParents.length).toEqual(1);
        expect(roleEditorParents).toEqual(jasmine.arrayContaining(['member']));

        expect(AclRegistryService.inherits('member', 'guest', true)).toBeTruthy();
        expect(AclRegistryService.inherits('editor', 'member', true)).toBeTruthy();
        expect(AclRegistryService.inherits('editor', 'guest')).toBeTruthy();

        expect(AclRegistryService.inherits('guest', 'member')).toBeFalsy();
        expect(AclRegistryService.inherits('member', 'editor')).toBeFalsy();
        expect(AclRegistryService.inherits('guest', 'editor')).toBeFalsy();
    });

    it('tests basic Role multiple inheritance with array', function () {
        AclRegistryService
            .add('parent1')
            .add('parent2')
            .add('child', ['parent1', 'parent2']);

        var roleChildParents = AclRegistryService.getParents('child');
        expect(roleChildParents.length).toEqual(2);
        expect(roleChildParents).toEqual(jasmine.arrayContaining(['parent1', 'parent2']));

        expect(AclRegistryService.inherits('child', 'parent1')).toBeTruthy();
        expect(AclRegistryService.inherits('child', 'parent2')).toBeTruthy();

        AclRegistryService.remove('parent2');

        roleChildParents = AclRegistryService.getParents('child');
        expect(roleChildParents.length).toEqual(1);
        expect(roleChildParents).toEqual(jasmine.arrayContaining(['parent1']));
        expect(AclRegistryService.inherits('child', 'parent1')).toBeTruthy();
    });

    it('ensures that the same Role cannot be registered more than once to the registry', function () {
        AclRegistryService.add('tst');

        expect(function() {
            AclRegistryService.add('tst');
        }).toThrowError();
    });

});