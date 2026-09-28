# DataFence v0.4 - Capability Architecture Evaluation

## Problem Statement

**Current Vulnerability:**
```python
# Attacker can forge ExecutionPlan
forged_plan = ExecutionPlan(...)

# Connector accepts without verification
connector.execute_plan(forged_plan)  # BREACH!
```

**Root Cause:**
The connector cannot distinguish between:
- ExecutionPlan from DataFence (authorized)
- ExecutionPlan from attacker (forged)

Python frozen dataclasses provide NO cryptographic integrity.

## Threat Models

### Threat Model A: Untrusted LLM/Agent (PRIMARY)
- Attacker controls LLM output, agent tool calls, request payloads
- Attacker can inspect public Python API
- Attacker does NOT control application code or Python runtime
- **This is the DataFence design goal**

### Threat Model B: Compromised Application Code
- Attacker can invoke DataFence APIs directly
- Attacker can import modules, instantiate classes
- Attacker does NOT have arbitrary Python runtime access
- **This is a stretch goal**

### Threat Model C: Full Python Runtime Compromise
- Attacker can execute arbitrary Python
- Attacker can monkey-patch, use object.__setattr__(), inspect internals
- **We explicitly do NOT defend against this**

## Architecture Options

### Option A: Private Constructors + Internal Token

```python
@dataclass(frozen=True)
class _AuthorizationToken:
    """Internal token - underscore suggests privacy."""
    secret: str = field(default_factory=lambda: uuid4().hex)

@dataclass(frozen=True)
class ExecutionPlan:
    execution_id: str
    actor: Actor
    resource: str
    # ...
    _token: Optional[_AuthorizationToken] = None
    
    @staticmethod
    def _create_authorized(actor, resource, ..., token: _AuthorizationToken):
        """Internal creation method used by DataFenceBoundary."""
        return ExecutionPlan(..., _token=token)
    
class DataFenceBoundary:
    def __init__(self):
        self._auth_token = _AuthorizationToken()
    
    def _create_execution_plan(self, ...):
        return ExecutionPlan._create_authorized(..., token=self._auth_token)

class SQLiteConnector:
    def __init__(self, db_path, expected_token: _AuthorizationToken):
        self._expected_token = expected_token
    
    def execute_plan(self, plan: ExecutionPlan):
        # Verify token
        if plan._token is None or plan._token != self._expected_token:
            raise SecurityError("Unauthorized ExecutionPlan")
        # Execute...
```

**Security Properties:**
- ✅ Prevents Threat Model A (LLM/agent cannot obtain token)
- ⚠️  Partially prevents Threat Model B (attacker can inspect `_token`)
- ❌ Does NOT prevent Threat Model C (Python introspection)

**Python Limitations:**
- `_token` is accessible via `plan._token`
- Attacker can do: `forged_plan = ExecutionPlan(..., _token=stolen_token)`
- Underscore is convention, not enforcement

**Complexity:** LOW
**Developer Ergonomics:** GOOD (simple API)
**Serialization:** Token must be excluded or becomes stealable
**Replay:** Token doesn't expire, can be reused

**Verdict:** ❌ **REJECT**
- Provides false sense of security
- Token can be stolen via introspection
- Does not satisfy even Threat Model B

---

### Option B: Opaque Capability Object

```python
class AuthorizedExecution:
    """
    Opaque capability created by DataFenceBoundary.
    
    This is NOT a dataclass - it's a controlled class with
    private internals.
    """
    
    def __init__(self, execution_id: str, actor: Actor, resource: str, ...):
        # Store internally
        self._execution_id = execution_id
        self._actor = actor
        self._resource = resource
        self._selected_fields = selected_fields
        self._enforced_filters = enforced_filters
        # ...
    
    # Read-only properties
    @property
    def execution_id(self) -> str:
        return self._execution_id
    
    @property
    def actor(self) -> Actor:
        return self._actor
    
    # NO public constructor - only created by DataFenceBoundary
    
class DataFenceBoundary:
    def _create_execution_plan(self, ...):
        return AuthorizedExecution(...)  # Only place this is created

class SQLiteConnector:
    def execute_plan(self, plan: AuthorizedExecution):
        # Type system enforces this is from DataFenceBoundary
        if not isinstance(plan, AuthorizedExecution):
            raise TypeError("Must be AuthorizedExecution")
        # Execute...
```

**Security Properties:**
- ✅ Prevents Threat Model A (LLM cannot create AuthorizedExecution)
- ⚠️  Partially prevents Threat Model B (attacker can call constructor directly)
- ❌ Does NOT prevent Threat Model C

**Python Limitations:**
- Constructor is still callable: `AuthorizedExecution(...)`
- Attacker can: `from datafence.core.capability import AuthorizedExecution`
- Python has no truly private constructors

**Complexity:** LOW
**Developer Ergonomics:** GOOD
**Serialization:** Difficult (need custom serialization)
**Replay:** No built-in prevention

**Verdict:** ⚠️  **PARTIAL**
- Better than Option A
- Still vulnerable if attacker can import the class
- Requires making AuthorizedExecution non-public

---

### Option C: Cryptographic Integrity (HMAC)

```python
import hmac
import hashlib
from secrets import token_bytes

@dataclass(frozen=True)
class ExecutionPlan:
    execution_id: str
    actor: Actor
    resource: str
    operation: Operation
    selected_fields: list[str]
    enforced_filters: dict[str, Any]
    limit: int
    policy_version: str
    policy_decisions: list[str]
    created_at: datetime
    
    # Cryptographic signature
    signature: bytes = field(default=b'')
    
    def _compute_signature(self, secret_key: bytes) -> bytes:
        """Compute HMAC signature over plan contents."""
        # Canonical representation
        data = f"{self.execution_id}|{self.actor.id}|{self.actor.tenant_id}|"
        data += f"{self.resource}|{self.operation.value}|"
        data += f"{','.join(sorted(self.selected_fields))}|"
        data += f"{json.dumps(self.enforced_filters, sort_keys=True)}|"
        data += f"{self.limit}|{self.policy_version}|"
        data += f"{self.created_at.isoformat()}"
        
        return hmac.new(secret_key, data.encode(), hashlib.sha256).digest()
    
    def verify_signature(self, secret_key: bytes) -> bool:
        """Verify plan was created by holder of secret_key."""
        expected = self._compute_signature(secret_key)
        return hmac.compare_digest(self.signature, expected)

class DataFenceBoundary:
    def __init__(self, policy_engine, connector):
        self.policy_engine = policy_engine
        self.connector = connector
        # Secret key - NEVER exposed publicly
        self._signing_key = token_bytes(32)
    
    def _create_execution_plan(self, ...):
        plan_unsigned = ExecutionPlan(
            execution_id=...,
            # ... all fields
            signature=b''  # Temporary
        )
        
        # Compute signature
        signature = plan_unsigned._compute_signature(self._signing_key)
        
        # Create signed plan (requires bypassing frozen=True)
        plan_signed = ExecutionPlan(
            # ... all fields
            signature=signature
        )
        
        return plan_signed

class SQLiteConnector:
    def __init__(self, db_path, signing_key: bytes):
        self.db_path = db_path
        self._signing_key = signing_key
    
    def execute_plan(self, plan: ExecutionPlan):
        # Cryptographic verification
        if not plan.verify_signature(self._signing_key):
            raise SecurityError("Invalid ExecutionPlan signature")
        
        # Execute...
```

**Security Properties:**
- ✅ Prevents Threat Model A (LLM cannot forge valid signature)
- ✅ Prevents Threat Model B (attacker cannot forge without secret key)
- ❌ Does NOT prevent Threat Model C (attacker can steal _signing_key)

**Python Limitations:**
- `_signing_key` can be accessed via introspection
- BUT: Threat Model C is explicitly out of scope
- Secret key must be shared between boundary and connector

**Complexity:** MEDIUM
- Need key management
- Need canonical serialization
- Need signature computation

**Developer Ergonomics:** GOOD
- ExecutionPlan remains a dataclass
- Transparent to users

**Serialization:** GOOD
- Signature travels with plan
- Can serialize/deserialize safely

**Replay:** No prevention (signature remains valid)

**Verdict:** ✅ **STRONG CANDIDATE**
- Provides cryptographic integrity
- Satisfies Threat Models A and B
- Complexity is manageable
- Key management is the challenge

---

### Option D: Boundary-Owned Execution

```python
class DataFenceBoundary:
    """
    The boundary owns execution completely.
    Connectors are NOT public.
    """
    
    def __init__(self, policy_engine, connector):
        self.policy_engine = policy_engine
        self._connector = connector  # PRIVATE
    
    def execute(self, actor: Actor, intent: Intent):
        # Authorization
        policy_decision = self._evaluate_policy(...)
        
        if policy_decision.decision == Decision.DENY:
            return DeniedRequest(...)
        
        # Create internal execution plan
        plan = self._create_execution_plan(...)
        
        # Execute via PRIVATE connector
        raw_data = self._connector.execute_plan(plan)
        
        # Validate and return
        result = self.validator.validate(plan, raw_data)
        return AllowedRequest(...)

# Connector is NEVER exported publicly
# It's an internal detail of DataFenceBoundary
```

**Security Properties:**
- ✅ Prevents Threat Model A (no way to reach connector)
- ✅ Prevents Threat Model B (connector not in public API)
- ❌ Does NOT prevent Threat Model C (can access _connector)

**Python Limitations:**
- `_connector` is still accessible via `boundary._connector`
- BUT: Requires attacking the boundary object

**Complexity:** LOW
**Developer Ergonomics:** EXCELLENT
- Simplest API: `boundary.execute(actor, intent)`
- No ExecutionPlan in public API
- No capability to steal

**Serialization:** N/A (execution is atomic)
**Replay:** N/A (no capability object)

**Verdict:** ✅ **STRONG CANDIDATE**
- Simplest architecture
- Smallest attack surface
- Forces authorization path

**Tradeoffs:**
- ❌ Cannot inspect ExecutionPlan externally
- ❌ Cannot queue/distribute execution plans
- ❌ Tightly couples boundary and connector

---

### Option E: Hybrid (HMAC + Boundary-Owned)

```python
class AuthorizedExecution:
    """
    Internal capability with HMAC signature.
    NOT exported publicly.
    """
    def __init__(self, ...):
        self._execution_id = ...
        self._signature = ...
    
    def verify(self, key: bytes) -> bool:
        # HMAC verification
        pass

class DataFenceBoundary:
    def __init__(self, policy_engine, connector):
        self._signing_key = token_bytes(32)
        self._connector = connector  # PRIVATE
    
    def execute(self, actor, intent):
        # Create signed capability (internal)
        capability = AuthorizedExecution(...)
        
        # Execute via private connector
        result = self._connector.execute(capability)
        
        return result

class _InternalConnector:
    """Internal connector - not exported."""
    def execute(self, capability: AuthorizedExecution):
        if not capability.verify(self._signing_key):
            raise SecurityError()
        # Execute...
```

**Security Properties:**
- ✅✅ Defense in depth
- ✅ Prevents Threat Model A
- ✅ Prevents Threat Model B
- ❌ Does NOT prevent Threat Model C

**Complexity:** MEDIUM-HIGH
**Developer Ergonomics:** EXCELLENT
**Serialization:** Possible (if needed)
**Replay:** Can add expiry to capability

**Verdict:** ✅ **STRONGEST OPTION**
- Combines best of C and D
- Defense in depth
- Flexibility for future (queuing, distribution)

---

## Comparison Matrix

| Option | Threat A | Threat B | Threat C | Complexity | Ergonomics | Serialization | Verdict |
|--------|----------|----------|----------|------------|------------|---------------|---------|
| A: Private Token | ✅ | ❌ | ❌ | LOW | GOOD | ❌ | ❌ REJECT |
| B: Opaque Capability | ✅ | ⚠️ | ❌ | LOW | GOOD | ⚠️ | ⚠️ PARTIAL |
| C: HMAC Signature | ✅ | ✅ | ❌ | MEDIUM | GOOD | ✅ | ✅ STRONG |
| D: Boundary-Owned | ✅ | ✅ | ❌ | LOW | EXCELLENT | N/A | ✅ STRONG |
| E: HMAC + Boundary | ✅ | ✅ | ❌ | MEDIUM | EXCELLENT | ✅ | ✅ STRONGEST |

---

## Recommendation

**CHOOSE OPTION E: Hybrid (HMAC + Boundary-Owned Execution)**

### Rationale

1. **Defense in Depth**
   - Boundary-owned execution prevents connector bypass
   - HMAC signature provides cryptographic integrity
   - Two independent security mechanisms

2. **Clear Trust Boundary**
   - Connector is NOT public
   - Capability is NOT public
   - Only `boundary.execute()` is public

3. **Satisfies Threat Models**
   - ✅ Threat Model A: LLM cannot forge or bypass
   - ✅ Threat Model B: Compromised app code cannot forge
   - ❌ Threat Model C: Explicitly out of scope

4. **Future Flexibility**
   - Can add capability expiry
   - Can support distributed execution (with serialization)
   - Can add replay protection
   - Can support execution queues

5. **Developer Experience**
   - Simple public API: `boundary.execute(actor, intent)`
   - Complex security is internal
   - No capability objects in application code

### Implementation Plan

1. **Create `AuthorizedExecution` capability** (internal, not exported)
   - HMAC signature over all fields
   - Verification method
   - Immutable

2. **Generate signing key in `DataFenceBoundary.__init__()`**
   - 32-byte random key via `secrets.token_bytes()`
   - Shared with connector
   - NEVER exposed publicly

3. **Make connector private**
   - `self._connector` in DataFenceBoundary
   - NOT exported in `__init__.py`
   - Only callable from boundary

4. **Connector verifies capability**
   - Check HMAC signature
   - Reject invalid capabilities
   - Log security events

5. **Remove ExecutionPlan from public API**
   - Keep for internal use
   - NOT exported in package
   - Evidence can reference it (read-only)

### Security Guarantees

**What we CAN guarantee:**
- Untrusted LLM/agent cannot execute operations without authorization
- Compromised application code cannot forge authorization
- Connector only executes cryptographically verified capabilities
- All execution goes through boundary (no bypass)

**What we CANNOT guarantee:**
- Protection against full Python runtime compromise (Threat Model C)
- Protection if signing key is leaked
- Protection if DataFence library is modified

### Trade-offs Accepted

- ❌ Cannot inspect ExecutionPlan externally (acceptable - use Evidence)
- ❌ Cannot manually construct capabilities (by design - security feature)
- ❌ Connector is not swappable at runtime (acceptable - set at construction)

---

## Alternative: Option D (Simpler)

If HMAC complexity is too high for v0.4, **Option D (Boundary-Owned Execution)** is acceptable:

**Pros:**
- Much simpler implementation
- Smaller attack surface
- Still satisfies Threat Models A and B

**Cons:**
- No cryptographic integrity
- Relies purely on API design
- Less defense in depth

**Recommendation:** Start with Option E, fall back to Option D if time-constrained.

---

## Addressing Actor Forgery

**Separate Problem:** Actor is caller-created, no authentication.

### Current Issue
```python
# Attacker can claim any identity
fake_actor = Actor(id="admin", tenant_id="victim")
boundary.execute(fake_actor, intent)  # Boundary trusts it!
```

### Solution
Actor authentication is OUT OF SCOPE for DataFence core.

**DataFence's responsibility:**
- Enforce policy for the provided Actor
- Ensure Actor identity is immutable during request
- Record Actor identity in evidence

**Application's responsibility:**
- Authenticate the Actor before calling DataFence
- Provide verified Actor object
- Manage identity and session

**Documentation must clarify:**
```python
# WRONG: Application creates Actor from untrusted input
actor = Actor(id=request.user, tenant_id=request.tenant)

# RIGHT: Application verifies identity first
session = authenticate_user(token)  # App's authentication
actor = Actor(id=session.user_id, tenant_id=session.tenant_id)
```

This is the same trust boundary as:
- User authentication in web frameworks
- Identity verification in auth middleware
- Session management

**No change needed** - document the trust boundary clearly.

---

## Summary

**Selected Architecture:** Option E (HMAC + Boundary-Owned Execution)

**Key Changes:**
1. Create internal `AuthorizedExecution` capability with HMAC
2. Make connector private (`_connector`)
3. Remove ExecutionPlan/connector from public API
4. Add cryptographic verification to connector
5. Document Actor trust boundary

**Security Outcome:**
- ✅ ExecutionPlan forgery: FIXED (capability has HMAC)
- ✅ Connector bypass: FIXED (connector is private)
- ✅ Tenant isolation: FIXED (enforced by boundary)
- ✅ Mutation: FIXED (HMAC covers all fields)
- ⚠️  Actor forgery: DOCUMENTED (application responsibility)

**Next:** Implement Option E in v0.4
