const { ethers } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');

async function fixture() {
  const [other] = await ethers.getSigners();
  const target = await ethers.deployContract('CallReceiverMockExtended');
  const anotherTarget = await ethers.deployContract('CallReceiverMockExtended');
  const mock = await ethers.deployContract('$ERC6900Utils');

  return { mock, target, anotherTarget, other };
}

describe('ERC6900Utils', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  describe('ValidationConfig', function () {
    it('get module', async function () {
      const validationConfig = ethers.solidityPacked(
        ['address', 'uint32', 'bytes1'],
        [this.target.target, 4512353, '0x01'],
      );
      await expect(this.mock.$module_ValidationConfig(validationConfig)).to.eventually.eq(this.target.target);
    });

    it('get entity', async function () {
      const entityId = 4512353n;
      const validationConfig = ethers.solidityPacked(
        ['address', 'uint32', 'bytes1'],
        [this.target.target, entityId, '0x01'],
      );
      await expect(this.mock.$entity_ValidationConfig(validationConfig)).to.eventually.eq(entityId);
    });

    it('get module entity', async function () {
      const moduleEntity = ethers.solidityPacked(['address', 'uint32'], [this.target.target, 4512353]);
      const validationConfig = ethers.solidityPacked(['bytes24', 'bytes1'], [moduleEntity, '0x01']);
      await expect(this.mock.$moduleEntity(validationConfig)).to.eventually.eq(moduleEntity);
    });

    it('get flags', async function () {
      const flags = '0x01';
      const validationConfig = ethers.solidityPacked(
        ['address', 'uint32', 'bytes1'],
        [this.target.target, 4512353, flags],
      );
      await expect(this.mock.$flags(validationConfig)).to.eventually.eq(flags);
    });
  });

  describe('ValidationFlags', function () {
    it('is global', async function () {
      const flags = buildValidationFlags(true);
      await expect(this.mock.$isGlobal(flags)).to.eventually.be.true;
    });

    it('is not global', async function () {
      const flags = buildValidationFlags(false);
      await expect(this.mock.$isGlobal(flags)).to.eventually.be.false;
    });

    it('is signature validation', async function () {
      const flags = buildValidationFlags(false, true);
      await expect(this.mock.$isSignatureValidation(flags)).to.eventually.be.true;
    });

    it('is not signature validation', async function () {
      const flags = buildValidationFlags();
      await expect(this.mock.$isSignatureValidation(flags)).to.eventually.be.false;
    });

    it('is user operation validation', async function () {
      const flags = buildValidationFlags(false, false, true);
      await expect(this.mock.$isUserOpValidation(flags)).to.eventually.be.true;
    });

    it('is not user operation validation', async function () {
      const flags = buildValidationFlags(false, false, false);
      await expect(this.mock.$isUserOpValidation(flags)).to.eventually.be.false;
    });
  });

  describe('HookConfig', function () {
    it('hasPre when true', async function () {
      const hookConfig = buildHookConfig(this.target.target, 4512353, buildHookFlags(true));
      await expect(this.mock.$hasPre(hookConfig)).to.eventually.be.true;
    });

    it('hasPre when false', async function () {
      const hookConfig = buildHookConfig(this.target.target, 4512353, buildHookFlags(false));
      await expect(this.mock.$hasPre(hookConfig)).to.eventually.be.false;
    });

    it('hasPost when true', async function () {
      const hookConfig = buildHookConfig(this.target.target, 4512353, buildHookFlags(false, true));
      await expect(this.mock.$hasPost(hookConfig)).to.eventually.be.true;
    });

    it('hasPost when false', async function () {
      const hookConfig = buildHookConfig(this.target.target, 4512353, buildHookFlags(false, false));
      await expect(this.mock.$hasPost(hookConfig)).to.eventually.be.false;
    });

    it('isValidationHook when true', async function () {
      const hookConfig = buildHookConfig(this.target.target, 4512353, buildHookFlags(false, false, 1));
      await expect(this.mock.$isValidationHook(hookConfig)).to.eventually.be.true;
    });

    it('isValidationHook when false (execution hook)', async function () {
      const hookConfig = buildHookConfig(this.target.target, 4512353, buildHookFlags(false, false, 0));
      await expect(this.mock.$isValidationHook(hookConfig)).to.eventually.be.false;
    });

    it('get module', async function () {
      const hookConfig = buildHookConfig(this.target.target, 4512353, buildHookFlags());
      await expect(this.mock.$module_HookConfig(hookConfig)).to.eventually.eq(this.target.target);
    });

    it('get entity', async function () {
      const entityId = 4512353n;
      const hookConfig = buildHookConfig(this.target.target, entityId, buildHookFlags());
      await expect(this.mock.$entity_HookConfig(hookConfig)).to.eventually.eq(entityId);
    });
  });

  describe('ModuleEntity', function () {
    it('get module', async function () {
      const moduleEntity = ethers.solidityPacked(['address', 'uint32'], [this.target.target, 4512353]);
      await expect(this.mock.$module(moduleEntity)).to.eventually.eq(this.target.target);
    });

    it('get entity', async function () {
      const entityId = 4512353n;
      const moduleEntity = ethers.solidityPacked(['address', 'uint32'], [this.target.target, entityId]);
      await expect(this.mock.$entity(moduleEntity)).to.eventually.eq(entityId);
    });
  });
});

const buildValidationFlags = (isGlobal = false, isSignatureValidation = false, isUserOpValidation = false) => {
  const isGlobalBit = (isGlobal ? 1 : 0) << 2;
  const isSignatureValidationBit = (isSignatureValidation ? 1 : 0) << 1;
  return ethers.toBeHex(BigInt(isGlobalBit | isSignatureValidationBit | (isUserOpValidation ? 1 : 0)), 1);
};

const buildHookConfig = (moduleAddress, entityId, flags) => {
  return ethers.solidityPacked(['address', 'uint32', 'bytes1'], [moduleAddress, entityId, flags]);
};

const buildHookFlags = (hasPre = false, hasPost = false, hookType = 0) => {
  const hasPreBit = (hasPre ? 1 : 0) << 2;
  const hasPostBit = (hasPost ? 1 : 0) << 1;
  return ethers.toBeHex(BigInt(hasPreBit | hasPostBit | hookType), 1);
};
