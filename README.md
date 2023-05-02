# EigenLayer_Contest_finding

## High Risk ##
1. ### Token Transfer Without Verification ###
One potential critical high-risk bug in this code is related to the line: **`paymentChallengeToken.safeTransferFrom(msg.sender, address(this), paymentChallengeAmount);`**

[LinkZ](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/middleware/PaymentManager.sol#L175-L226)
### Impact ###
This line transfers tokens from the sender to the contract address, without verifying if the transfer was successful or not. This means that if the transfer fails for any reason (e.g., insufficient balance, incorrect token address, or other reasons), the function will still continue to execute, and the operator's payment claim will be recorded even though they did not put up the required tokens. This could lead to a situation where the operator makes a fraudulent payment claim, and the contract cannot slash their tokens to prevent fraud.

### Proof of Concept

```solidity
enum PaymentStatus { NONE, COMMITTED, REDEEMED }

struct Payment {
    uint32 fromTaskNumber;
    uint32 toTaskNumber;
    uint32 confirmAt;
    uint96 amount;
    PaymentStatus status;
    uint96 paymentChallengeAmount;
}

mapping(address => Payment) operatorToPayment;

function commitPayment(uint32 toTaskNumber, uint96 amount) external onlyWhenNotPaused(PAUSED_NEW_PAYMENT_COMMIT) {
    // Only active operators can call
    require(registry.isActiveOperator(msg.sender), "PaymentManager.commitPayment: Only registered operators can call this function");

    // Ensure the operator has redeemed their last payment
    Payment storage lastPayment = operatorToPayment[msg.sender];
    require(lastPayment.status == PaymentStatus.REDEEMED, "PaymentManager.commitPayment: Require last payment is redeemed");

    // Ensure the operator is not claiming future payments
    require(toTaskNumber <= _taskNumber(), "PaymentManager.commitPayment: Cannot claim future payments");

    // Calculate the fromTaskNumber for the operator
    uint32 fromTaskNumber = lastPayment.toTaskNumber == 0 ? registry.getFromTaskNumberForOperator(msg.sender) : lastPayment.toTaskNumber;
    require(fromTaskNumber < toTaskNumber, "invalid payment range");

    // Put up tokens which can be slashed in case of wrongful payment claim
    uint96 paymentChallengeAmount = getPaymentChallengeAmount(amount);
    paymentChallengeToken.safeTransferFrom(msg.sender, address(this), paymentChallengeAmount);

    // Record the payment claims for the operator
    operatorToPayment[msg.sender] = Payment(
        fromTaskNumber,
        toTaskNumber,
        uint32(block.timestamp + paymentFraudproofInterval),
        amount,
        PaymentStatus.COMMITTED,
        paymentChallengeAmount
    );

    emit PaymentCommit(msg.sender, fromTaskNumber, toTaskNumber, amount);
}

```

### Recommendations

To solve this problem, you need to ensure that the **`toTaskNumber`** argument passed to the **`commitPayment`** function is not greater than the **`_taskNumber()`** function result.

One way to fix this is to make sure that the **`_taskNumber()`** function returns the correct value, and that it is updated whenever a new task is added. You should also ensure that the **`toTaskNumber`** argument passed to the **`commitPayment`** function is obtained from a reliable source, such as an external contract or an authenticated user.
You can modify the **`require`** statement to provide a more informative error message to help with debugging, for example:

```solidity
javascriptCopy code
require(
    toTaskNumber <= _taskNumber(),
    "PaymentManager.commitPayment: Cannot claim payments for future tasks"
);

```

In the updated code, we first retrieve the last payment made by the operator and ensure that it has been redeemed. We then calculate the fromTaskNumber for the current payment, based on whether the operator has made any previous payments or not. We then check that the payment range is valid, i.e., fromTaskNumber < toTaskNumber. Finally, we put up tokens for slashing and record the payment claims for the operator.

2. ### Function Triggering ###
### Impact ###

The ````redeemPayment()```` funtion does not check if the payment token being transferred to the delegation terms contract is approved by the sender. This can allow an attacker to call this function and transfer any ERC-20 token to any arbitrary address by exploiting the approve() function of a payment token contract.
[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/middleware/PaymentManager.sol#L232-L263)
### **Proof of Concept**

```solidity
function redeemPayment() external onlyWhenNotPaused(PAUSED_REDEEM_PAYMENT) {
    // verify that the `msg.sender` has a committed payment
    require(
        operatorToPayment[msg.sender].status == PaymentStatus.COMMITTED,
        "PaymentManager.redeemPayment: Payment Status is not 'COMMITTED'"
    );

    // check that the fraudproof period has already transpired
    require(
        block.timestamp > operatorToPayment[msg.sender].confirmAt,
        "PaymentManager.redeemPayment: Payment still eligible for fraudproof"
    );

    // update the status to show that operator's payment is getting redeemed
    operatorToPayment[msg.sender].status = PaymentStatus.REDEEMED;

    // Transfer back the challengeAmount to the operator as there was no successful challenge to the payment commitment made by the operator.
    paymentChallengeToken.safeTransfer(msg.sender, operatorToPayment[msg.sender].challengeAmount);

    // look up payment amount and delegation terms address for the `msg.sender`
    uint256 amount = operatorToPayment[msg.sender].amount;
    IDelegationTerms dt = delegationManager.delegationTerms(msg.sender);

    // transfer the amount due in the payment claim of the operator to its delegation terms contract, where the delegators can withdraw their rewards.
    require(paymentToken.transferFrom(msg.sender, address(dt), amount), "PaymentManager.redeemPayment: Payment token transfer failed");

    // emit event
    emit PaymentRedemption(msg.sender, amount);

    // inform the DelegationTerms contract of the payment, which will determine the rewards the operator and its delegators are eligible for
    _payForServiceHook(dt, amount);
}

```

### **Recommendations**
In the modified function, we replaced the ````safeTransfer()```` function call with a call to ````transferFrom()````. We also added a ````require()```` statement to ensure that the transfer is successful.

# Low or Non-Critical Vulnerabilities

From lines 15 - 84; [LinkA](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/Slasher.sol#L21-L88)

From lines 200 - 292; [LinkB](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/Slasher.sol#L200-L292)

- The **`_revokeSlashingAbility`** function that is called within **`recordLastStakeUpdateAndRevokeSlashingAbility`** is not defined in this code snippet, so we can't assess its safety.
-The **`whitelistedContractDetails`** function returns a struct, which may be expensive in terms of gas usage. Additionally, there may be some concerns about exposing internal data structures like this to external callers.
-The **`canSlash`** function uses the **`block.number`** variable, which is the current block number and is therefore subject to manipulation by miners. This could potentially be exploited by malicious actors to bypass slashing restrictions.
-The **`isFrozen`** function checks if an address is frozen or not, but it is unclear what the implications of being frozen are or how freezing is triggered.
-The **`canWithdraw`** function contains a potentially confusing condition involving the **`size`** property of a data structure, which may be difficult for external callers to reason about.

### Reentrancy ###

- The contract uses the `Pausable` contract from OpenZeppelin, which exposes the `whenNotPaused` modifier that is applied to external functions. However, this does not protect against reentrancy attacks that can occur if the contract modifies state after an external call.[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/Slasher.sol)
- The comments warn against depositing tokens that allow reentrancy, but it's not clear from the code if this is completely prevented. If a malicious actor were able to trigger a reentrant call, they could potentially manipulate the balances of the contract and the strategy, leading to a loss of funds. (line 164 to line 298).[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/StrategyManager.sol#L164-L298)

### Integer Overflow ###

The uint256 data type is used throughout the code, but it's not clear if any checks are made to prevent integer overflow. An unchecked integer overflow can result in incorrect calculations, which can lead to unintended behavior or an attack that exploits this vulnerability. [Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/StrategyManager.sol#L164-L298)

### Signature verification ###

The depositIntoStrategyWithSignature function requires a signature for validation, but it's not clear from the code how the signature is being verified. If the verification process is not secure, then a malicious actor could generate a fake signature and deposit funds on behalf of another user.[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/StrategyManager.sol)

### Lack of access control

[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/StrategyManager.sol)
There doesn't appear to be any access control mechanisms in place for certain functions, such as strategyWhitelister and withdrawalDelayBlocks, which could lead to unauthorized changes to these values.

### Lack of input validation

[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/StrategyManager.sol)
There is no input validation in the nonces mapping, which could lead to nonce reuse and replay attacks. Additionally, there is no input validation in the beaconChainETHSharesToDecrementOnWithdrawal mapping, which could lead to incorrect withdrawal amounts.

### Information leakage

The `_whitelistedContractDetails` mapping stores sensitive information about the contract's operators and the middleware with permission to slash them. Anyone who can read the storage of the contract can access this information.[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/Slasher.sol)

### External call to untrusted contract

The freezeOperator function allows external contracts to call it and modify the frozenStatus mapping. This could lead to potential vulnerabilities if an untrusted contract is allowed to call this function.[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/Slasher.sol)

### Lack of validation

The contract uses the `_optIntoSlashing` function to give permission to contracts to slash the funds of the caller. However, there is no validation to ensure that the contract being given permission is a valid contract. This could lead to potential vulnerabilities if a malicious contract is given permission to slash the funds of the caller.`[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/Slasher.sol)

### Signature validity check

The delegateToBySignature() function includes a check for the validity of a signature provided by the staker. The check differs depending on whether the staker is a contract or an externally owned account (EOA). However, if the contract does not implement the EIP-1271 standard correctly, this check may not be effective, and an attacker may be able to bypass it.[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/DelegationManager.sol)

# Gas Optimization

1. **Unused imports**

There are unused imports. They will increase the size of deployment with no real benefit. An example of such an import is:

```
import "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol";
import "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import "../src/contracts/interfaces/IDelegationManager.sol";

```

## Recommended Mitigation Steps

Consider removing unused imports to save some gas

### 2. Refactoring mappings

Could potentially save some gas, depending on the usage patterns of the contract.

Packing Data into a Single Mapping: If multiple pieces of data are associated with each address in the mappings, such as in the case of **`operatorShares`** and **`delegationTerms`**, it may be possible to pack this data into a single mapping. For example, instead of having two separate mappings:

```
typescriptCopy code
mapping(address => mapping(IStrategy => uint256)) public operatorShares;
mapping(address => IDelegationTerms) public delegationTerms;

```

We could have a single mapping that stores a struct containing both pieces of data:

```
scssCopy code
struct OperatorInfo {
    mapping(IStrategy => uint256) shares;
    IDelegationTerms delegationTerms;
}
mapping(address => OperatorInfo) public operatorInfo;

```

This can potentially save gas by reducing the number of storage slots used by the contract, as well as reducing the number of SSTORE operations needed to modify the mappings.

**Alternatively;** Arrays for One-to-Many Relationships:

1. In the case of **`delegatedTo`**, it may be possible to save gas by using an array to store the addresses that have delegated to each operator, instead of using a separate mapping for each operator. For example, we could change the mapping:

```
cssCopy code
mapping(address => address) public delegatedTo;

```

To an array:

```
cssCopy code
mapping(address => address[]) public operators;

```

And add a function to add an address to the array:

```
arduinoCopy code
function delegateTo(address operator) public {
    delegatedTo[msg.sender] = operator;
    operators[operator].push(msg.sender);
}

```

This can potentially save gas by reducing the number of storage slots used by the contract, as well as reducing the number of SSTORE operations needed to modify the mappings.

### 

1. The contract uses the StructuredLinkedList library, which may result in high gas costs when the list becomes large.[Link](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/core/Slasher.sol)

## **Medium Vulnerability:**
### low-level call functionality ### [LinkQ](https://github.com/code-423n4/2023-04-eigenlayer/blob/5e4872358cd2bda1936c29f460ece2308af4def6/src/contracts/middleware/PaymentManager.sol#L266-L337)

### Impact ###

The **`_payForServiceHook()`** function uses low-level call functionality which can be used by an attacker to trigger a reentrancy attack and drain the contract's funds.

### **Proof of Concept**

```
solidityCopy code
// create a malicious contract
contract MaliciousContract {
    PaymentManager public paymentManager;
    IDelegationTerms public delegationTerms;
    uint256 public amountToSteal;

    constructor(PaymentManager _paymentManager) {
        paymentManager = _paymentManager;
        delegationTerms = IDelegationTerms(address(this));
        amountToSteal = 1 ether;
    }

    // fallback function to trigger reentrancy attack
    fallback() external payable {
        if (address(paymentManager).balance >= amountToSteal) {
            paymentManager.withdraw({ from: address(delegationTerms) });
        }
    }

    // function to initiate the reentrancy attack
    function attack(IDelegationTerms _delegationTerms) external {
        delegationTerms = _delegationTerms;
        paymentManager.payForService(address(this), amountToSteal);
    }
}

// deploy the PaymentManager contract
let paymentManager = await PaymentManager.deployed();

// create a malicious contract
let maliciousContract = await MaliciousContract.new(paymentManager.address);

// call `_payForServiceHook()` with the malicious contract as the DelegationTerms contract
await paymentManager._payForServiceHook(maliciousContract, 1 ether);

// initiate the reentrancy attack
await maliciousContract.attack(IDelegationTerms(address(this)));

```

### **Recommendations**

To fix this vulnerability, the contract should use the **`call`** method with the **`check-effects-interaction`** pattern to prevent reentrancy attacks. This pattern separates the state-changing operations from the contract calls and allows the contract to complete the state-changing operations before executing the call, preventing reentrancy attacks.
The PaymentManager contract has three functions that could potentially introduce security vulnerabilities.

The **`_updateChallengeAmounts`** function does not check for overflow or underflow when adding **`amount1`** and **`amount2`** before comparing them with the stored amounts in **`operatorToPaymentChallenge`**. An attacker could use this vulnerability to bypass the challenge process by supplying large or small values for **`amount1`** and **`amount2`**. A possible fix would be to add an additional check to ensure that **`amount1`** and **`amount2`** are within the appropriate range.

The **`resolveChallenge`** function does not have a reentrancy guard, which could enable an attacker to repeatedly call the **`_resolve`** function and drain funds from the contract. A possible fix would be to add a reentrancy guard to the **`_resolve`** function.

The functions that access the **`operatorToPaymentChallenge`** and **`operatorToPayment`** mappings do not check that the **`operator`** address is valid. An attacker could use this vulnerability to supply a non-existent **`operator`** address and cause the function to throw an error or behave unexpectedly. A possible fix would be to add a check for a valid **`operator`** address before accessing the mappings.
