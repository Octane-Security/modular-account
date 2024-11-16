// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import {getEmptyCalldataSlice} from "@erc6900/reference-implementation/helpers/EmptyCalldataSlice.sol";
import {ExecutionManifest} from "@erc6900/reference-implementation/interfaces/IExecutionModule.sol";
import {
    Call,
    HookConfig,
    IModularAccount,
    ModuleEntity,
    ValidationConfig
} from "@erc6900/reference-implementation/interfaces/IModularAccount.sol";
import {HookConfig, HookConfigLib} from "@erc6900/reference-implementation/libraries/HookConfigLib.sol";
import {ModuleEntityLib} from "@erc6900/reference-implementation/libraries/ModuleEntityLib.sol";
import {SparseCalldataSegmentLib} from "@erc6900/reference-implementation/libraries/SparseCalldataSegmentLib.sol";
import {ValidationConfigLib} from "@erc6900/reference-implementation/libraries/ValidationConfigLib.sol";
import {IAccountExecute} from "@eth-infinitism/account-abstraction/interfaces/IAccountExecute.sol";
import {IEntryPoint} from "@eth-infinitism/account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "@eth-infinitism/account-abstraction/interfaces/PackedUserOperation.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/interfaces/IERC1155Receiver.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

import {ExecutionInstallDelegate} from "../helpers/ExecutionInstallDelegate.sol";
import {_coalescePreValidation, _coalesceValidation} from "../helpers/ValidationResHelpers.sol";

import {IModularAccountBase} from "../interfaces/IModularAccountBase.sol";
import {
    DensePostHookData,
    ExecutionLib,
    PHCallBuffer,
    RTCallBuffer,
    SigCallBuffer,
    UOCallBuffer
} from "../libraries/ExecutionLib.sol";
import {LinkedListSet, LinkedListSetLib} from "../libraries/LinkedListSetLib.sol";
import {MemManagementLib, MemSnapshot} from "../libraries/MemManagementLib.sol";
import {
    ValidationLocator, ValidationLocatorLib, ValidationLookupKey
} from "../libraries/ValidationLocatorLib.sol";
import {AccountBase} from "./AccountBase.sol";
import {AccountStorage, ValidationStorage, getAccountStorage, toSetValue} from "./AccountStorage.sol";
import {AccountStorageInitializable} from "./AccountStorageInitializable.sol";
import {ModularAccountView} from "./ModularAccountView.sol";
import {ModuleManagerInternals} from "./ModuleManagerInternals.sol";
import {TokenReceiver} from "./TokenReceiver.sol";

/// @title Modular Account Base
/// @author Alchemy
/// @notice This abstract contract is a modular account that is compliant with ERC-6900 standard. It supports
/// deferred actions during validation.
abstract contract ModularAccountBase is
    IModularAccount,
    IModularAccountBase,
    ModularAccountView,
    AccountStorageInitializable,
    AccountBase,
    IERC1271,
    IERC165,
    IAccountExecute,
    ModuleManagerInternals,
    UUPSUpgradeable,
    TokenReceiver
{
    using LinkedListSetLib for LinkedListSet;
    using ModuleEntityLib for ModuleEntity;
    using ValidationConfigLib for ValidationConfig;
    using HookConfigLib for HookConfig;
    using SparseCalldataSegmentLib for bytes;
    // temp, remove after updating validation selection
    using ValidationLocatorLib for ModuleEntity;

    enum ValidationCheckingType {
        GLOBAL,
        SELECTOR,
        EITHER
    }

    // keccak256("EIP712Domain(uint256 chainId,address verifyingContract)")
    bytes32 internal constant _DOMAIN_SEPARATOR_TYPEHASH =
        0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    // keccak256("DeferredAction(uint256 nonce,uint48 deadline,uint168 validationLocator,bytes call)")
    bytes32 internal constant _DEFERRED_ACTION_TYPEHASH =
        0xa0a7682d80b18373e0ec8549850bc960f46562e16ae4ddee86ab9a3cc3d3a07c;

    // As per the EIP-165 spec, no interface should ever match 0xffffffff
    bytes4 internal constant _INTERFACE_ID_INVALID = 0xffffffff;

    // bytes4(keccak256("isValidSignature(bytes32,bytes)"))
    bytes4 internal constant _1271_MAGIC_VALUE = 0x1626ba7e;
    bytes4 internal constant _1271_INVALID = 0xffffffff;

    uint8 internal constant _IS_GLOBAL_VALIDATION_BIT = 1;
    uint8 internal constant _HAS_DEFERRED_ACTION_BIT = 2;

    address internal immutable _EXECUTION_INSTALL_DELEGATE;

    event DeferredActionNonceInvalidated(uint256 nonce);

    error CreateFailed();
    error DeferredActionNonceInvalid();
    error DeferredActionSignatureInvalid();
    error RequireUserOperationContext();
    error SelfCallRecursionDepthExceeded();
    error SignatureValidationInvalid(ModuleEntity validationFunction);
    error UserOpValidationInvalid(ModuleEntity validationFunction);
    error UnexpectedAggregator(ModuleEntity validationFunction, address aggregator);
    error UnrecognizedFunction(bytes4 selector);
    error ValidationFunctionMissing(bytes4 selector);
    error DeferredValidationHasValidationHooks();

    // Wraps execution of a native function with runtime validation and hooks
    // Used for upgradeTo, upgradeToAndCall, execute, executeBatch, installExecution, uninstallExecution,
    // performCreate
    modifier wrapNativeFunction() {
        DensePostHookData postHookData = _checkPermittedCallerAndAssociatedHooks();

        _;

        ExecutionLib.doCachedPostHooks(postHookData);
    }

    constructor(IEntryPoint anEntryPoint) AccountBase(anEntryPoint) {
        _disableInitializers();

        _EXECUTION_INSTALL_DELEGATE = address(new ExecutionInstallDelegate());
    }

    // EXTERNAL FUNCTIONS

    receive() external payable {}

    /// @notice Fallback function
    /// @dev Routes calls to execution functions based on the incoming msg.sig. If there's no module associated
    /// with this function selector, revert.
    ///
    /// @return The raw returned data from the invoked execution function.
    fallback(bytes calldata) external payable returns (bytes memory) {
        address execModule = getAccountStorage().executionStorage[msg.sig].module;
        if (execModule == address(0)) {
            revert UnrecognizedFunction(msg.sig);
        }
        DensePostHookData postHookData = _checkPermittedCallerAndAssociatedHooks();

        // execute the function, bubbling up any reverts
        ExecutionLib.callBubbleOnRevertTransient(execModule, 0 wei, msg.data);
        bytes memory execReturnData = ExecutionLib.collectReturnData();

        ExecutionLib.doCachedPostHooks(postHookData);

        return execReturnData;
    }

    /// @inheritdoc IModularAccountBase
    function performCreate(uint256 value, bytes calldata initCode, bool isCreate2, bytes32 salt)
        external
        payable
        virtual
        override
        wrapNativeFunction
        returns (address createdAddr)
    {
        assembly ("memory-safe") {
            // Load the free memory pointer.
            let fmp := mload(0x40)

            // Get the initCode length.
            let len := initCode.length

            // Copy the initCode from callata to memory at the free memory pointer.
            calldatacopy(fmp, initCode.offset, len)

            switch isCreate2
            case 1 { createdAddr := create2(value, fmp, len, salt) }
            default { createdAddr := create(value, fmp, len) }

            if iszero(createdAddr) {
                // If creation failed (the address returned is zero), revert with CreateFailed().
                mstore(0x00, 0x7e16b8cd)
                revert(0x1c, 0x04)
            }
        }
    }

    /// @inheritdoc IAccountExecute
    /// @notice Execution function that allows UO context to be passed to execution hooks
    /// @dev This function is only callable by the EntryPoint
    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external override {
        _requireFromEntryPoint();

        (ValidationLocator locator,) = ValidationLocatorLib.loadFromSignature(userOp.signature);

        HookConfig[] memory validationAssocExecHooks =
            MemManagementLib.loadExecHooks(getAccountStorage().validationStorage[locator.lookupKey()]);

        PHCallBuffer callBuffer;
        if (validationAssocExecHooks.length > 0) {
            callBuffer = ExecutionLib.allocatePreExecHookCallBuffer(msg.data);
        }

        DensePostHookData postHookData = ExecutionLib.doPreHooks(validationAssocExecHooks, callBuffer);

        bytes memory callData = ExecutionLib.getExecuteUOCallData(callBuffer, userOp.callData);

        // Manually call self, without collecting return data unless there's a revert.
        ExecutionLib.callBubbleOnRevert(address(this), 0, callData);

        ExecutionLib.doCachedPostHooks(postHookData);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    function execute(address target, uint256 value, bytes calldata data)
        external
        payable
        override
        wrapNativeFunction
        returns (bytes memory result)
    {
        ExecutionLib.callBubbleOnRevertTransient(target, value, data);

        // Only return data if not called by the EntryPoint
        if (msg.sender != address(_ENTRY_POINT)) {
            result = ExecutionLib.collectReturnData();
        }
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation function.
    function executeBatch(Call[] calldata calls)
        external
        payable
        override
        wrapNativeFunction
        returns (bytes[] memory results)
    {
        bool needReturnData = (msg.sender != address(_ENTRY_POINT));

        uint256 callsLength = calls.length;

        if (needReturnData) {
            results = new bytes[](callsLength);
        }

        for (uint256 i = 0; i < callsLength; ++i) {
            ExecutionLib.callBubbleOnRevertTransient(calls[i].target, calls[i].value, calls[i].data);

            if (needReturnData) {
                results[i] = ExecutionLib.collectReturnData();
            }
        }
    }

    /// @inheritdoc IModularAccount
    function executeWithRuntimeValidation(bytes calldata data, bytes calldata authorization)
        external
        payable
        returns (bytes memory)
    {
        (ValidationLocator locator, bytes calldata authorizationData) =
            ValidationLocatorLib.loadFromSignature(authorization);

        ValidationStorage storage _validationStorage = getAccountStorage().validationStorage[locator.lookupKey()];

        // Check if the runtime validation function is allowed to be called
        _checkIfValidationAppliesCallData(
            data,
            locator.lookupKey(),
            // Unfortunately, have to avoid declaring a `bool isGlobalValidation` to avoid stack too deep issues.
            locator.isGlobal() ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
        );

        RTCallBuffer rtCallBuffer = _doRuntimeValidation(locator, data, authorizationData);

        // If runtime validation passes, run exec hooks associated with the validator
        HookConfig[] memory validationAssocExecHooks = MemManagementLib.loadExecHooks(_validationStorage);

        PHCallBuffer phCallBuffer;
        if (validationAssocExecHooks.length > 0) {
            phCallBuffer = ExecutionLib.convertToPreHookCallBuffer(rtCallBuffer, data);
        }
        DensePostHookData postHookData = ExecutionLib.doPreHooks(validationAssocExecHooks, phCallBuffer);

        // Execute the call, reusing the already-allocated RT call buffers, if it exists.
        // In practice, this is cheaper than attempting to coalesce the (possibly two) buffers.
        ExecutionLib.executeRuntimeSelfCall(rtCallBuffer, data);
        bytes memory returnData = ExecutionLib.collectReturnData();

        ExecutionLib.doCachedPostHooks(postHookData);

        return returnData;
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    function installExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleInstallData
    ) external override wrapNativeFunction {
        // Access params to prevent compiler unused parameter flags.
        (module, manifest, moduleInstallData);
        address delegate = _EXECUTION_INSTALL_DELEGATE;
        ExecutionLib.delegatecallBubbleOnRevertTransient(delegate);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    function uninstallExecution(
        address module,
        ExecutionManifest calldata manifest,
        bytes calldata moduleUninstallData
    ) external override wrapNativeFunction {
        // Access params to prevent compiler unused parameter flags.
        (module, manifest, moduleUninstallData);
        address delegate = _EXECUTION_INSTALL_DELEGATE;
        ExecutionLib.delegatecallBubbleOnRevertTransient(delegate);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    /// @dev This function can be used to update (to a certain degree) previously installed validation functions.
    ///      - preValidationHook, executionHooks, and selectors can be added later. Though they won't be deleted.
    ///      - isGlobal and isSignatureValidation can also be updated later.
    function installValidation(
        ValidationConfig validationConfig,
        bytes4[] calldata selectors,
        bytes calldata installData,
        bytes[] calldata hooks
    ) external wrapNativeFunction {
        _installValidation(validationConfig, selectors, installData, hooks);
    }

    /// @inheritdoc IModularAccount
    /// @notice May be validated by a global validation.
    function uninstallValidation(
        ModuleEntity validationFunction,
        bytes calldata uninstallData,
        bytes[] calldata hookUninstallData
    ) external wrapNativeFunction {
        _uninstallValidation(validationFunction, uninstallData, hookUninstallData);
    }

    /// @inheritdoc IModularAccountBase
    function invalidateDeferredValidationInstallNonce(uint256 nonce) external override wrapNativeFunction {
        getAccountStorage().deferredActionNonceUsed[nonce] = true;
        emit DeferredActionNonceInvalidated(nonce);
    }

    /// @inheritdoc IERC165
    /// @notice ERC-165 introspection
    /// @dev returns true for `IERC165.interfaceId` and false for `0xFFFFFFFF`
    /// @param interfaceId interface id to check against
    /// @return bool support for specific interface
    function supportsInterface(bytes4 interfaceId) external view override returns (bool) {
        if (interfaceId == _INTERFACE_ID_INVALID) {
            return false;
        }
        if (
            interfaceId == type(IERC721Receiver).interfaceId || interfaceId == type(IERC1155Receiver).interfaceId
                || interfaceId == type(IERC165).interfaceId
        ) {
            return true;
        }

        return getAccountStorage().supportedIfaces[interfaceId] > 0;
    }

    /// @inheritdoc IModularAccount
    function accountId() external pure virtual returns (string memory);

    /// @inheritdoc UUPSUpgradeable
    /// @notice May be validated by a global validation.
    function upgradeToAndCall(address newImplementation, bytes calldata data)
        public
        payable
        virtual
        override
        onlyProxy
        wrapNativeFunction
    {
        super.upgradeToAndCall(newImplementation, data);
    }

    /// @inheritdoc IERC1271
    function isValidSignature(bytes32 hash, bytes calldata signature) public view override returns (bytes4) {
        (ValidationLocator locator, bytes calldata signatureRemainder) =
            ValidationLocatorLib.loadFromSignature(signature);

        return _isValidSignature(locator, hash, signatureRemainder);
    }

    // INTERNAL FUNCTIONS

    // Parent function validateUserOp enforces that this call can only be made by the EntryPoint
    function _validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        override
        returns (uint256 validationData)
    {
        (ValidationLocator locator, bytes calldata userOpSignature) =
            ValidationLocatorLib.loadFromSignature(userOp.signature);

        /// The calldata layout is unique for deferred validation installation.
        /// Byte indices are [inclusive, exclusive] and relative to the start of the signature after the locator is
        /// decoded and removed.
        ///      [0:4] : uint32, encodedDatalength.
        ///      [4:(4 + encodedDatalength)] : bytes, abi-encoded deferred action data.
        ///      [(4 + encodedDataLength):(8 + encodedDataLength)] : uint32, deferredActionSigLength.
        ///      [(8 + encodedDataLength):(8 + deferredActionSigLength + encodedDataLength)] : bytes,
        ///         deferred action sig. This is the signature passed to the outer validation decoded earlier.
        ///      [(8 + deferredActionSigLength + encodedDataLength):] : bytes, userOpSignature. This is the
        ///         signature passed to the inner validation.
        if (locator.hasDeferredAction()) {
            // Use inner validation as a 1271 validation for the deferred action, then use the outer
            // validation to validate the UO.

            // Get the length of the deferred action data.
            uint256 encodedDataLength = uint32(bytes4(userOpSignature[:4]));

            // Load the pointer to the encoded data.
            bytes calldata encodedData = userOpSignature[4:4 + encodedDataLength];

            // Get the deferred action signature length.
            uint256 deferredActionSigLength =
                uint32(bytes4(userOpSignature[4 + encodedDataLength:8 + encodedDataLength]));

            // Get the deferred installation signature, which is passed to the outer validation to handle the
            // deferred action.
            bytes calldata deferredActionSig =
                userOpSignature[8 + encodedDataLength:8 + encodedDataLength + deferredActionSigLength];

            //Validate the signature.

            // Freeze the free-memory pointer, since we won't need to use anything from the deferred action
            // validation memory.
            MemSnapshot memSnapshot = MemManagementLib.freezeFMP();

            uint48 deadline = _handleDeferredAction(locator, encodedData, deferredActionSig);

            // Restore the free memory pointer.
            MemManagementLib.restoreFMP(memSnapshot);

            // Update the validation data with the deadline.
            validationData = uint256(deadline) << 160;

            // Update the UserOp signature to the remaining bytes.
            userOpSignature = userOpSignature[8 + encodedDataLength + deferredActionSigLength:];
        }

        _checkIfValidationAppliesCallData(
            userOp.callData,
            locator.lookupKey(),
            locator.isGlobal() ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
        );

        // Check if there are execution hooks associated with the validator, and revert if the call isn't to
        // `executeUserOp`. This check must be here because if context isn't passed, we can't tell in execution
        // which hooks should have ran.
        if (
            getAccountStorage().validationStorage[locator.lookupKey()].executionHookCount > 0
                && bytes4(userOp.callData[:4]) != this.executeUserOp.selector
        ) {
            revert RequireUserOperationContext();
        }
        uint256 userOpValidationRes = _doUserOpValidation(userOp, userOpHash, locator, userOpSignature);

        // We only coalesce validations if the validation data from deferred installation is nonzero.
        if (validationData != 0) {
            validationData = _coalesceValidation(validationData, userOpValidationRes);
        } else {
            validationData = userOpValidationRes;
        }
    }

    /// @return The deadline of the deferred action
    function _handleDeferredAction(ValidationLocator locator, bytes calldata encodedData, bytes calldata sig)
        internal
        returns (uint48)
    {
        // The deadline, nonce, inner validation, and deferred call selector are all at fixed positions in the
        // encodedData.

        // todo: this will need to get encoded differently
        ValidationConfig defActionSigValidation = ValidationConfig.wrap(bytes25(encodedData[38:63]));
        bool isGlobalSigValidation = defActionSigValidation.isGlobal();

        ModuleEntity defActionValidationModuleEntity = defActionSigValidation.moduleEntity();

        // Because this bypasses UO validation hooks, we require that the validation used does not include any
        // validation hooks.
        if (
            getAccountStorage().validationStorage[defActionValidationModuleEntity.moduleEntityToLookup()]
                .validationHookCount != 0
        ) {
            revert DeferredValidationHasValidationHooks();
        }

        // Check if the outer validation applies to the function call
        _checkIfValidationAppliesCallData(
            encodedData[63:],
            defActionValidationModuleEntity.moduleEntityToLookup(),
            isGlobalSigValidation ? ValidationCheckingType.GLOBAL : ValidationCheckingType.SELECTOR
        );

        // Handle the signature validation
        uint48 deadline =
            _validateDeferredActionSignature(encodedData, sig, locator, defActionValidationModuleEntity);

        // Run the validation associated execution hooks, allocating a call buffer as needed.
        HookConfig[] memory validationAssocExecHooks = MemManagementLib.loadExecHooks(
            getAccountStorage().validationStorage[defActionValidationModuleEntity.moduleEntityToLookup()]
        );

        PHCallBuffer callBuffer;
        if (validationAssocExecHooks.length > 0) {
            callBuffer = ExecutionLib.allocatePreExecHookCallBuffer(encodedData[63:]);
        }

        DensePostHookData postHookData = ExecutionLib.doPreHooks(validationAssocExecHooks, callBuffer);

        // Perform the deferred action's self call on the account.
        ExecutionLib.callBubbleOnRevertTransient(address(this), 0, encodedData[63:]);

        // Do the cached post hooks
        ExecutionLib.doCachedPostHooks(postHookData);

        return deadline;
    }

    // To support gas estimation, we don't fail early when the failure is caused by a signature failure
    function _doUserOpValidation(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        ValidationLocator validationLocator,
        bytes calldata signature
    ) internal returns (uint256) {
        ValidationStorage storage _validationStorage =
            getAccountStorage().validationStorage[validationLocator.lookupKey()];

        // Do preUserOpValidation hooks
        HookConfig[] memory preUserOpValidationHooks = MemManagementLib.loadValidationHooks(_validationStorage);

        ModuleEntity userOpValidationFunction = validationLocator.moduleEntity(_validationStorage);

        uint256 validationRes;
        UOCallBuffer userOpCallBuffer;
        if (!_validationIsNative(userOpValidationFunction) || preUserOpValidationHooks.length > 0) {
            userOpCallBuffer = ExecutionLib.allocateUserOpValidationCallBuffer(userOp, userOpHash);
        }
        bytes calldata currentSignatureSlice;
        for (uint256 i = preUserOpValidationHooks.length; i > 0; i) {
            // Decrement here, instead of in the loop body, to convert from length to an index.
            unchecked {
                --i;
            }

            (currentSignatureSlice, signature) =
                signature.advanceSegmentIfAtIndex(uint8(preUserOpValidationHooks.length - i - 1));

            ModuleEntity uoValidationHook = preUserOpValidationHooks[i].moduleEntity();

            uint256 currentValidationRes =
                ExecutionLib.invokeUserOpCallBuffer(userOpCallBuffer, uoValidationHook, currentSignatureSlice);

            if (uint160(currentValidationRes) > 1) {
                // If the aggregator is not 0 or 1, it is an unexpected value
                revert UnexpectedAggregator(uoValidationHook, address(uint160(currentValidationRes)));
            }
            validationRes = _coalescePreValidation(validationRes, currentValidationRes);
        }

        // Run the user op validation function
        {
            currentSignatureSlice = signature.getFinalSegment();

            uint256 currentValidationRes = _execUserOpValidation(
                userOpValidationFunction, userOpHash, currentSignatureSlice, userOpCallBuffer
            );

            if (preUserOpValidationHooks.length != 0) {
                // If we have other validation data we need to coalesce with
                validationRes = _coalesceValidation(validationRes, currentValidationRes);
            } else {
                validationRes = currentValidationRes;
            }
        }

        return validationRes;
    }

    function _doRuntimeValidation(
        ValidationLocator validationLocator,
        bytes calldata callData,
        bytes calldata authorizationData
    ) internal returns (RTCallBuffer) {
        ValidationStorage storage _validationData =
            getAccountStorage().validationStorage[validationLocator.lookupKey()];

        // run all preRuntimeValidation hooks
        HookConfig[] memory preRuntimeValidationHooks = MemManagementLib.loadValidationHooks(_validationData);

        ModuleEntity runtimeValidationFunction = validationLocator.moduleEntity(_validationData);

        RTCallBuffer callBuffer;
        if (!_validationIsNative(runtimeValidationFunction) || preRuntimeValidationHooks.length > 0) {
            callBuffer = ExecutionLib.allocateRuntimeValidationCallBuffer(callData, authorizationData);
        }

        for (uint256 i = preRuntimeValidationHooks.length; i > 0;) {
            // Decrement here, instead of in the loop update step, to handle the case where the length is 0.
            unchecked {
                --i;
            }

            bytes calldata currentAuthSegment;

            (currentAuthSegment, authorizationData) =
                authorizationData.advanceSegmentIfAtIndex(uint8(preRuntimeValidationHooks.length - i - 1));

            ExecutionLib.invokeRuntimeCallBufferPreValidationHook(
                callBuffer, preRuntimeValidationHooks[i], currentAuthSegment
            );
        }

        authorizationData = authorizationData.getFinalSegment();

        _execRuntimeValidation(runtimeValidationFunction, callBuffer, authorizationData);

        return callBuffer;
    }

    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override {}

    /**
     * Order of operations:
     *      1. Check if the sender is the entry point, the account itself, or the selector called is public.
     *          - Yes: Return an empty array, there are no post executionHooks.
     *          - No: Continue
     *      2. Check if the called selector (msg.sig) is included in the set of selectors the msg.sender can
     *         directly call.
     *          - Yes: Continue
     *          - No: Revert, the caller is not allowed to call this selector
     *      3. If there are runtime validation hooks associated with this caller-sig combination, run them.
     *      4. Run the pre executionHooks associated with this caller-sig combination, and return the
     *         post executionHooks to run later.
     */
    function _checkPermittedCallerAndAssociatedHooks() internal returns (DensePostHookData) {
        AccountStorage storage _storage = getAccountStorage();
        HookConfig[] memory execHooks;

        RTCallBuffer rtCallBuffer;

        // We only need to handle execution hooks when the sender is not the entry point or the account itself,
        // and the selector isn't public.
        if (
            msg.sender != address(_ENTRY_POINT) && msg.sender != address(this)
                && !_storage.executionStorage[msg.sig].skipRuntimeValidation
        ) {
            ValidationLookupKey directCallValidationKey = ValidationLocatorLib.directCallLookup(msg.sender);

            _checkIfValidationAppliesCallData(msg.data, directCallValidationKey, ValidationCheckingType.EITHER);

            // Direct call is allowed, run associated execution & validation hooks

            // Validation hooks
            HookConfig[] memory preRuntimeValidationHooks =
                MemManagementLib.loadValidationHooks(_storage.validationStorage[directCallValidationKey]);

            uint256 preRuntimeValidationHooksLength = preRuntimeValidationHooks.length;
            if (preRuntimeValidationHooksLength > 0) {
                rtCallBuffer = ExecutionLib.allocateRuntimeValidationCallBuffer(msg.data, getEmptyCalldataSlice());
            }

            for (uint256 i = preRuntimeValidationHooksLength; i > 0;) {
                // Decrement here, instead of in the loop body, to convert from length to an index.
                unchecked {
                    --i;
                }

                ExecutionLib.invokeRuntimeCallBufferPreValidationHook(
                    rtCallBuffer, preRuntimeValidationHooks[i], getEmptyCalldataSlice()
                );
            }

            //Load all execution hooks: both associated with the selector and the validation function.
            execHooks = MemManagementLib.loadExecHooks(
                _storage.executionStorage[msg.sig], _storage.validationStorage[directCallValidationKey]
            );
        } else {
            // If the sender is the entry point or the account itself, or the selector is public, this indicates
            // that validation was done elsewhere. We only need to run selector-associated execution hooks.
            execHooks = MemManagementLib.loadExecHooks(_storage.executionStorage[msg.sig]);
        }

        PHCallBuffer preHookCallBuffer;
        if (execHooks.length > 0) {
            preHookCallBuffer = ExecutionLib.convertToPreHookCallBuffer(rtCallBuffer, msg.data);
        }

        // Exec hooks associated with the selector
        DensePostHookData postHookData = ExecutionLib.doPreHooks(execHooks, preHookCallBuffer);

        return postHookData;
    }

    function _execUserOpValidation(
        ModuleEntity userOpValidationFunction,
        bytes32,
        bytes calldata signatureSegment,
        UOCallBuffer callBuffer
    ) internal virtual returns (uint256) {
        AccountStorage storage _storage = getAccountStorage();

        if (!_storage.validationStorage[userOpValidationFunction.moduleEntityToLookup()].isUserOpValidation) {
            revert UserOpValidationInvalid(userOpValidationFunction);
        }

        ExecutionLib.convertToValidationBuffer(callBuffer);

        return ExecutionLib.invokeUserOpCallBuffer(callBuffer, userOpValidationFunction, signatureSegment);
    }

    function _execRuntimeValidation(
        ModuleEntity runtimeValidationFunction,
        RTCallBuffer callBuffer,
        bytes calldata authorization
    ) internal virtual {
        ExecutionLib.invokeRuntimeCallBufferValidation(callBuffer, runtimeValidationFunction, authorization);
    }

    function _validateDeferredActionSignature(
        bytes calldata encodedData,
        bytes calldata signature,
        ValidationLocator locator,
        ModuleEntity deferredSigValidationModuleEntity
    ) internal returns (uint48) {
        uint256 nonce = uint256(bytes32(encodedData[:32]));
        uint48 deadline = uint48(bytes6(encodedData[32:38]));

        // Check that the passed nonce isn't already invalidated.
        if (getAccountStorage().deferredActionNonceUsed[nonce]) {
            revert DeferredActionNonceInvalid();
        }

        // Invalidate the nonce.
        getAccountStorage().deferredActionNonceUsed[nonce] = true;
        emit DeferredActionNonceInvalidated(nonce);

        // Compute the hash without permanently allocating memory for each step.
        // The following is equivalent to:
        // keccak256(
        //     abi.encode(
        //         _DEFERRED_ACTION_TYPEHASH,
        //         nonce,
        //         deadline,
        //         validationFunction,
        //         keccak256(selfCall)
        //     )
        // )

        // Note that a zero deadline translates to "no deadline"

        // Fetch the self-call from the encoded data.
        bytes calldata selfCall = encodedData[63:];

        // Compute the typed data hash.
        bytes32 typedDataHash;
        {
            bytes32 structHash;

            assembly ("memory-safe") {
                // Get the hash of the dynamic-length encoded install call
                let fmp := mload(0x40)
                calldatacopy(fmp, selfCall.offset, selfCall.length)
                let selfCallHash := keccak256(fmp, selfCall.length)

                // Compute the struct hash
                let ptr := fmp
                mstore(ptr, _DEFERRED_ACTION_TYPEHASH)
                ptr := add(ptr, 0x20)
                mstore(ptr, nonce)
                ptr := add(ptr, 0x20)
                // Clear the upper bits of the deadline, in case the caller didn't.
                mstore(ptr, and(deadline, 0xffffffffffff))
                ptr := add(ptr, 0x20)
                // Clear the upper bits of the validation locator, in case the caller didn't.
                mstore(ptr, and(locator, 0xffffffffffffffffffffffffffffffffffffffffff))
                ptr := add(ptr, 0x20)
                mstore(ptr, selfCallHash)

                // Compute the struct hash
                structHash := keccak256(fmp, 0xa0)
            }

            typedDataHash = MessageHashUtils.toTypedDataHash(_domainSeparator(), structHash);
        }

        // Validate the 1271 signature.
        SigCallBuffer sigCallBuffer;
        if (!_validationIsNative(deferredSigValidationModuleEntity)) {
            sigCallBuffer = ExecutionLib.allocateSigCallBuffer(typedDataHash, signature);
        }

        if (
            _exec1271Validation(sigCallBuffer, typedDataHash, deferredSigValidationModuleEntity, signature)
                != _1271_MAGIC_VALUE
        ) {
            revert DeferredActionSignatureInvalid();
        }

        return deadline;
    }

    function _isValidSignature(ValidationLocator validationLocator, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bytes4)
    {
        ValidationStorage storage _validationStorage =
            getAccountStorage().validationStorage[validationLocator.lookupKey()];

        HookConfig[] memory preSignatureValidationHooks = MemManagementLib.loadValidationHooks(_validationStorage);

        ModuleEntity sigValidation = validationLocator.moduleEntity(_validationStorage);

        SigCallBuffer sigCallBuffer;
        if (!_validationIsNative(sigValidation) || preSignatureValidationHooks.length > 0) {
            sigCallBuffer = ExecutionLib.allocateSigCallBuffer(hash, signature);
        }
        for (uint256 i = preSignatureValidationHooks.length; i > 0;) {
            // Decrement here, instead of in the loop body, to convert from length to an index.
            unchecked {
                --i;
            }

            bytes calldata currentSignatureSegment;

            (currentSignatureSegment, signature) =
                signature.advanceSegmentIfAtIndex(uint8(preSignatureValidationHooks.length - i - 1));

            ExecutionLib.invokePreSignatureValidationHook(
                sigCallBuffer, preSignatureValidationHooks[i], currentSignatureSegment
            );
        }
        signature = signature.getFinalSegment();

        return _exec1271Validation(sigCallBuffer, hash, sigValidation, signature);
    }

    function _exec1271Validation(
        SigCallBuffer buffer,
        bytes32 hash,
        ModuleEntity sigValidation,
        bytes calldata signatureSegment
    ) internal view virtual returns (bytes4) {
        (hash); // unused in ModularAccountBase, but used in SemiModularAccountBase
        AccountStorage storage _storage = getAccountStorage();

        if (!_storage.validationStorage[sigValidation.moduleEntityToLookup()].isSignatureValidation) {
            revert SignatureValidationInvalid(sigValidation);
        }

        if (ExecutionLib.invokeSignatureValidation(buffer, sigValidation, signatureSegment) == _1271_MAGIC_VALUE) {
            return _1271_MAGIC_VALUE;
        }
        return _1271_INVALID;
    }

    function _isValidationGlobal(ValidationLookupKey validationFunction) internal view virtual returns (bool) {
        return getAccountStorage().validationStorage[validationFunction].isGlobal;
    }

    function _checkIfValidationAppliesCallData(
        bytes calldata callData,
        ValidationLookupKey validationFunction,
        ValidationCheckingType checkingType
    ) internal view {
        // address(4).staticcall(abi.encodePacked(validationFunction));

        if (callData.length < 4) {
            revert UnrecognizedFunction(bytes4(callData));
        }

        bytes4 outerSelector = bytes4(callData);
        if (outerSelector == this.executeUserOp.selector) {
            // If the selector is executeUserOp, pull the actual selector from the following data,
            // and trim the calldata to ensure the self-call decoding is still accurate.
            callData = callData[4:];
            outerSelector = bytes4(callData[:4]);
        }

        _checkIfValidationAppliesSelector(outerSelector, validationFunction, checkingType);

        if (outerSelector == IModularAccount.execute.selector) {
            address target = MemManagementLib.getExecuteTarget(callData);

            if (target == address(this)) {
                // There is no point to call `execute` to recurse exactly once - this is equivalent to just having
                // the calldata as a top-level call.
                revert SelfCallRecursionDepthExceeded();
            }
        } else if (outerSelector == IModularAccount.executeBatch.selector) {
            // executeBatch may be used to batch account actions together, by targetting the account itself.
            // If this is done, we must ensure all of the inner calls are allowed by the provided validation
            // function.
            _checkExecuteBatchValidationApplicability(callData[4:], validationFunction, checkingType);
        }
    }

    /// @notice Checks if the validation function is allowed to perform this call to `executeBatch`.
    /// @param callData The calldata to check, excluding the `executeBatch` selector.
    /// @param validationFunction The validation function to check against.
    /// @param checkingType The type of validation checking to perform.
    function _checkExecuteBatchValidationApplicability(
        bytes calldata callData,
        ValidationLookupKey validationFunction,
        ValidationCheckingType checkingType
    ) internal view {
        // Equivalent to the following code, but without using memory.

        // (Call[] memory calls) = abi.decode(callData[4:], (Call[]));

        // for (uint256 i = 0; i < calls.length; ++i) {
        //     if (calls[i].target == address(this)) {
        //         bytes4 nestedSelector = bytes4(calls[i].data[:4]);

        //         if (
        //             nestedSelector == IModularAccount.execute.selector
        //                 || nestedSelector == IModularAccount.executeBatch.selector
        //         ) {
        //
        //             revert SelfCallRecursionDepthExceeded();
        //         }

        //         _checkIfValidationAppliesSelector(nestedSelector, validationFunction, checkingType);
        //     }
        // }

        // The following is adapted from the compiler-generated ABI decoder for the `Call[] calldata` parameter
        // type. See test/mocks/MockDecoder.sol for more info.
        // This allows the decoding behavior here, in the validation step, to match what would happen during the
        // actual execution of `executeBatch`.
        // This follows the compiler-generated behavior of:
        // - asserting the data to load fits in the remaining space of the current `bytes calldata`.
        // - asserting that the ABI-encoded offsets and lengths do not exceed the constant value
        // 0xffffffffffffffff.

        // The end of allowed calldata to read. Declared in an outer context to make available to multiple code
        // blocks.
        uint256 dataEnd;

        // The absolute offset of the start of the `Call[]` array.
        uint256 arrayPos;
        // The length of the `Call[]` array.
        uint256 callsLength;

        // This block is retrieving the actual Call[] location and length, asserting it doesn't go out of bounds.
        assembly ("memory-safe") {
            // Set up the "safe data decoding range"
            let headStart := callData.offset
            dataEnd := add(headStart, callData.length)

            // Assert it is safe to load the offset
            if slt(sub(dataEnd, headStart), 32) { revert(0, 0) }

            // Load and sanitize the offset
            let relOffset := calldataload(callData.offset)
            if gt(relOffset, 0xffffffffffffffff) { revert(0, 0) }

            // Convert from a relative offset to an absolute offset.
            let absOffset := add(headStart, relOffset)

            // Assert it is safe to load the length
            if iszero(slt(add(absOffset, 0x1f), dataEnd)) { revert(0, 0) }

            // Load and sanitize the length
            callsLength := calldataload(absOffset)
            if gt(callsLength, 0xffffffffffffffff) { revert(0, 0) }

            // Load the array position, and check that it fits within the alloted length.
            arrayPos := add(absOffset, 0x20)
            if gt(add(arrayPos, mul(callsLength, 0x20)), dataEnd) { revert(0, 0) }
        }

        // Now, we have the array length and data bounds.
        // Iterate through the array elements, checking:
        // - If the target is this account, assert that:
        //   - the selector in the data field is not `execute` or `executeBatch`.
        //   - the provided validation is allowed to call the selector.

        for (uint256 i = 0; i < callsLength; ++i) {
            address callTarget;
            uint256 structAbsOffset;

            // This block is retrieving the actual calls[i] struct location and contents, asserting it doesn't go
            // out of bounds.
            assembly ("memory-safe") {
                // Load and sanitize the struct offset.
                // This is still safe to load, from the bounds check above.
                let structRelOffset := calldataload(add(arrayPos, mul(i, 0x20)))
                if gt(structRelOffset, 0xffffffffffffffff) { revert(0, 0) }
                // Validate struct offset. If the offset points to a location with < 3 words of space before the
                // end of data, revert.
                if iszero(slt(structRelOffset, sub(sub(dataEnd, arrayPos), sub(0x60, 1)))) { revert(0, 0) }

                structAbsOffset := add(arrayPos, structRelOffset)

                // Load the address from the struct, and sanitize its contents, to mirror the behavior of the ABI
                // decoder.
                callTarget := calldataload(structAbsOffset)
                if iszero(eq(and(callTarget, 0xffffffffffffffffffffffffffffffffffffffff), callTarget)) {
                    revert(0, 0)
                }
            }

            if (callTarget == address(this)) {
                // In this case, we must load the selector, deny if it's `execute` or `executeBatch`, and check
                // validation applicability.

                uint32 selector;

                // This block is retrieving the selector from the first 4 bytes of calls[i].data, asserting it
                // doesn't go out of bounds and that the data is at least 4 bytes long.
                assembly ("memory-safe") {
                    // Load and sanitize the data offset.
                    let dataRelOffset := calldataload(add(structAbsOffset, 0x40))
                    if gt(dataRelOffset, 0xffffffffffffffff) { revert(0, 0) }

                    // Validate data offset. If the offset points to a location with < 1 words of space before the
                    // end of data, revert.
                    if iszero(slt(dataRelOffset, sub(sub(dataEnd, structAbsOffset), sub(0x20, 1)))) {
                        revert(0, 0)
                    }

                    let dataAbsOffset := add(structAbsOffset, dataRelOffset)

                    // Load and sanitize the data length.
                    let dataLength := calldataload(dataAbsOffset)
                    if gt(dataLength, 0xffffffff) { revert(0, 0) }

                    // Get the data offset, and assert that the following data fits into the bounded calldata
                    // range.
                    let dataOffset := add(dataAbsOffset, 0x20)
                    if sgt(dataOffset, sub(dataEnd, mul(dataLength, 0x01))) { revert(0, 0) }

                    // Finally, load the selector being called. This will be the first 4 bytes of the data.
                    // If the data length is less than 4, revert.
                    if slt(dataLength, 4) { revert(0, 0) }
                    selector := shr(224, calldataload(dataOffset))
                }

                if (selector == uint32(this.execute.selector) || selector == uint32(this.executeBatch.selector)) {
                    // To prevent arbitrarily-deep recursive checking, we limit the depth of self-calls to one
                    // for the purposes of batching.
                    // This means that all self-calls must occur at the top level of the batch.
                    // Note that modules of other contracts using `executeWithRuntimeValidation` may still
                    // independently call into this account with a different validation function, allowing
                    // composition of multiple batches.

                    revert SelfCallRecursionDepthExceeded();
                }

                _checkIfValidationAppliesSelector(bytes4(selector), validationFunction, checkingType);
            }
        }
    }

    function _checkIfValidationAppliesSelector(
        bytes4 selector,
        ValidationLookupKey validationFunction,
        ValidationCheckingType checkingType
    ) internal view {
        // Check that the provided validation function is applicable to the selector

        if (checkingType == ValidationCheckingType.GLOBAL) {
            if (!_globalValidationApplies(selector, validationFunction)) {
                revert ValidationFunctionMissing(selector);
            }
        } else if (checkingType == ValidationCheckingType.SELECTOR) {
            if (!_selectorValidationApplies(selector, validationFunction)) {
                revert ValidationFunctionMissing(selector);
            }
        } else {
            if (
                !_globalValidationApplies(selector, validationFunction)
                    && !_selectorValidationApplies(selector, validationFunction)
            ) {
                revert ValidationFunctionMissing(selector);
            }
        }
    }

    function _globalValidationApplies(bytes4 selector, ValidationLookupKey validationFunction)
        internal
        view
        returns (bool)
    {
        return _globalValidationAllowed(selector) && _isValidationGlobal(validationFunction);
    }

    function _globalValidationAllowed(bytes4 selector) internal view virtual returns (bool) {
        return _isGlobalValidationAllowedNativeFunction(selector)
            || getAccountStorage().executionStorage[selector].allowGlobalValidation;
    }

    function _selectorValidationApplies(bytes4 selector, ValidationLookupKey validationFunction)
        internal
        view
        returns (bool)
    {
        return getAccountStorage().validationStorage[validationFunction].selectors.contains(toSetValue(selector));
    }

    function _domainSeparator() internal view returns (bytes32) {
        bytes32 result;

        // Compute the hash without permanently allocating memory
        assembly ("memory-safe") {
            let fmp := mload(0x40)
            mstore(fmp, _DOMAIN_SEPARATOR_TYPEHASH)
            mstore(add(fmp, 0x20), chainid())
            mstore(add(fmp, 0x40), address())
            result := keccak256(fmp, 0x60)
        }

        return result;
    }

    // A virtual function to detect if a validation function is natively implemented. Used for determining call
    // buffer allocation.
    function _validationIsNative(ModuleEntity) internal pure virtual returns (bool) {
        return false;
    }
}
