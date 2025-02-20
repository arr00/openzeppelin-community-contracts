const { ethers } = require('hardhat');
const { expect } = require('chai');
const { loadFixture } = require('@nomicfoundation/hardhat-network-helpers');
const { impersonate } = require('@openzeppelin/contracts/test/helpers/account');

async function fixture() {
  const [other] = await ethers.getSigners();
  const target = await ethers.deployContract('CallReceiverMockExtended');
  const anotherTarget = await ethers.deployContract('CallReceiverMockExtended');
  const executionHookModule = await ethers.deployContract('$ERC6900ExecutionHookModuleMock');
  const validationHookModule = await ethers.deployContract('$ERC6900ValidationHookModuleMock');
  const validationModule = await ethers.deployContract('$ERC6900ValidationModuleMock');
  const executionModule = await ethers.deployContract('$ERC6900ModuleMock');
  const mock = await ethers.deployContract('$AccountERC6900Mock', ['MockERC6900', '1.0']);
  const entrypointAddress = await mock.entryPoint();
  const entrypointSigner = await impersonate(entrypointAddress);

  return {
    mock,
    target,
    anotherTarget,
    other,
    validationModule,
    validationHookModule,
    executionHookModule,
    executionModule,
    entrypointSigner,
  };
}

describe('AccountERC6900', function () {
  beforeEach(async function () {
    Object.assign(this, await loadFixture(fixture));
  });

  describe('Install Execution', function () {
    it('execution module skip runtime validation', async function () {
      const executionManifest = {
        executionFunctions: [
          { executionSelector: '0x12345678', skipRuntimeValidation: true, allowGlobalValidation: false },
        ],
        executionHooks: [],
        interfaceIds: [],
      };
      await expect(
        this.mock
          .connect(this.entrypointSigner)
          .installExecution(this.executionModule.target, executionManifest, '0x34'),
      )
        .to.emit(this.executionModule, 'OnInstall')
        .withArgs('0x34');

      // Now anyone can directly call that function
      const tx = {
        to: this.mock.target,
        data: '0x123456781234',
      };

      await expect(this.other.sendTransaction(tx))
        .to.emit(this.executionModule, 'FallbackExecution')
        .withArgs('0x12345678', '0x1234');
    });

    it('execution module with hook', async function () {
      const executionManifest = {
        executionFunctions: [
          { executionSelector: '0x12345678', skipRuntimeValidation: true, allowGlobalValidation: false },
        ],
        executionHooks: [{ executionSelector: '0x12345678', entityId: 0, isPreHook: true, isPostHook: true }],
        interfaceIds: [],
      };
      await this.mock
        .connect(this.entrypointSigner)
        .installExecution(this.executionHookModule.target, executionManifest, '0x34');

      const tx = {
        to: this.mock.target,
        data: '0x123456781234',
      };

      await expect(this.other.sendTransaction(tx))
        .to.emit(this.executionHookModule, 'OnPreExecutionHook')
        .withArgs(0, this.other, 0, '0x123456781234')
        .to.emit(this.executionHookModule, 'OnPostExecutionHook')
        .withArgs(0, '0x');
    });

    it('execution selectors', async function () {
      const interfaceId1 = '0x12345678';
      const interfaceId2 = '0x87654321';

      const executionManifest = {
        executionFunctions: [],
        executionHooks: [],
        interfaceIds: [interfaceId1, interfaceId2],
      };

      for (const interfaceId of [interfaceId1, interfaceId2]) {
        await expect(this.mock.supportsInterface(interfaceId)).to.eventually.be.false;
      }

      await this.mock
        .connect(this.entrypointSigner)
        .installExecution(this.executionModule.target, executionManifest, '0x');

      for (const interfaceId of [interfaceId1, interfaceId2]) {
        await expect(this.mock.supportsInterface(interfaceId)).to.eventually.be.true;
      }
    });
  });
});
