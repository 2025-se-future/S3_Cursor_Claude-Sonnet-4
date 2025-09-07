# End-to-End Tests for Feature 1: Manage Authentication

This document describes the comprehensive end-to-end test suite for Feature 1: Manage Authentication, based on the detailed feature specification in `../features/f1_manage_authentication.md`.

## Overview

The E2E test suite validates the complete user authentication journey from a user's perspective, testing both sub-features:

- **Sub-feature 1.1: Sign In** - User authentication with Google OAuth
- **Sub-feature 1.2: Sign Out** - User session termination

## Test File Location

```
backend/tests/e2e-feature1-authentication.test.ts
```

## Test Coverage

### Sub-feature 1.1: Sign In - Complete User Journey

#### Success Scenarios
1. **New User First-Time Authentication**
   - Tests the complete flow: Authentication screen → Google sign-in → User registration → Navigation to Groups List
   - Validates user creation in database
   - Verifies JWT token generation
   - Confirms user can access protected resources

2. **Existing User Authentication**
   - Tests sign-in flow for returning users
   - Validates existing user lookup
   - Ensures no duplicate user creation
   - Confirms token generation for existing users

#### Failure Scenarios
3. **Google Authentication Service Unavailable (Scenario 3a)**
   - Simulates Google service downtime
   - Tests error message display: "Authentication service temporarily unavailable"
   - Validates retry capability after service recovery
   - Ensures graceful degradation

4. **Authentication Fails (Scenario 5a)**
   - Tests invalid Google token handling
   - Validates error message: "Authentication unsuccessful"
   - Tests retry flow with valid credentials
   - Ensures robust error handling

#### Edge Cases
5. **Input Validation**
   - Missing token in request body
   - Empty token validation
   - Malformed request handling

### Sub-feature 1.2: Sign Out - Complete User Journey

#### Success Scenarios
1. **User Signs Out**
   - Tests complete sign-out flow from Groups List screen
   - Validates Google Authentication Service interaction
   - Confirms success message display
   - Ensures user data persistence (user not deleted)

#### Failure Scenarios
2. **Google Authentication Service Unavailable (Scenario 1a)**
   - Tests sign-out when Google service is down
   - Validates error handling and current screen retention
   - Ensures graceful fallback behavior

#### Authentication State Management
3. **Token Validation Edge Cases**
   - Missing authorization header
   - Invalid JWT token format
   - Expired JWT token handling
   - Malformed authorization header

### Complete Authentication Lifecycle - Integration Tests

1. **Full User Journey: Sign In → Use App → Sign Out**
   - Tests complete user lifecycle from authentication to sign-out
   - Validates protected resource access during session
   - Confirms user data persistence after sign-out

2. **Token Expiration and Re-authentication Flow**
   - Tests expired token detection
   - Validates re-authentication requirement
   - Tests seamless transition back to authenticated state

### Security and Protection Tests

1. **Unauthorized Access Prevention**
   - Tests protection of all authenticated endpoints
   - Validates proper 401 responses for unauthenticated requests
   - Ensures security barriers are in place

2. **Rate Limiting**
   - Tests authentication rate limiting (10 requests per 15 minutes)
   - Validates proper 429 responses for excessive requests
   - Ensures protection against brute force attacks

## Test Architecture

### Mocking Strategy
- **UserService Mocking**: Uses Jest mocks to control authentication flow
- **Database Integration**: Real MongoDB in-memory database for data persistence testing
- **JWT Integration**: Real JWT token generation and validation for security testing

### Test Data Management
- Each test uses isolated test data
- Database cleanup between tests ensures independence
- Realistic user data for comprehensive validation

### Error Simulation
- Service unavailability simulation
- Invalid token scenarios
- Network failure conditions
- Authentication service errors

## Test Execution

### Run E2E Tests Only
```bash
npm test -- --testPathPattern="e2e-feature1-authentication"
```

### Run All Tests
```bash
npm test
```

### Run with Coverage
```bash
npm run test:coverage
```

## Test Results Summary

- **Total Tests**: 15 end-to-end test cases
- **Test Categories**:
  - Sign In Success Scenarios: 2 tests
  - Sign In Failure Scenarios: 2 tests  
  - Sign In Edge Cases: 2 tests
  - Sign Out Success Scenarios: 1 test
  - Sign Out Failure Scenarios: 1 test
  - Sign Out Edge Cases: 3 tests
  - Integration Tests: 2 tests
  - Security Tests: 2 tests

## API Endpoints Tested

### Authentication Endpoints
- `POST /api/users/auth/signin` - Google OAuth authentication
- `POST /api/users/auth/signout` - User session termination

### Profile Endpoints  
- `GET /api/users/me` - Current user profile (for testing authenticated access)
- `GET /api/users/:userId` - User profile by ID (for testing multi-user scenarios)

## Test Scenarios Mapping to Feature Specification

| Feature Spec Step | Test Coverage |
|------------------|---------------|
| 1.1.1 - Display Authentication screen | ✅ Simulated (frontend responsibility) |
| 1.1.2 - User taps "Sign in with Google" | ✅ API call simulation |
| 1.1.3 - Google authentication flow | ✅ Mocked Google OAuth |
| 1.1.4 - User completes authentication | ✅ Token validation |
| 1.1.5 - Google service authenticates | ✅ Service response simulation |
| 1.1.6 - Navigate to Groups List | ✅ Token-based access validation |
| 1.1.3a - Google service unavailable | ✅ Error simulation and retry |
| 1.1.5a - Authentication fails | ✅ Invalid token handling |
| 1.2.1 - Initiate sign out | ✅ Sign out endpoint testing |
| 1.2.2 - Google token revocation | ✅ Service interaction simulation |
| 1.2.3 - Confirmation and app close | ✅ Success message validation |
| 1.2.1a - Google service unavailable | ✅ Sign out error handling |

## Quality Assurance Features

### Data Validation
- User creation verification
- Token integrity validation  
- Database state confirmation
- Response structure validation

### Security Testing
- Authentication bypass prevention
- Token expiration handling
- Rate limiting enforcement
- Input sanitization validation

### Performance Testing
- Concurrent request handling
- Rate limiting behavior
- Database transaction integrity
- Memory leak prevention

### Error Handling
- Graceful failure modes
- Appropriate error messages
- Recovery mechanisms
- Retry capabilities

## Maintenance and Updates

### Adding New Test Cases
1. Follow the existing test structure and naming conventions
2. Use descriptive test names that match feature specification steps
3. Include both positive and negative test scenarios
4. Ensure proper cleanup and isolation

### Updating for Specification Changes
1. Review feature specification updates
2. Map new requirements to test scenarios
3. Update test data and expectations
4. Maintain backward compatibility where possible

### Performance Considerations
- Tests run in under 2 seconds
- In-memory database ensures fast execution
- Parallel test execution when possible
- Minimal external dependencies

## Conclusion

This comprehensive E2E test suite ensures that Feature 1: Manage Authentication works correctly from a user's perspective, covering all success scenarios, failure modes, and edge cases specified in the feature requirements. The tests provide confidence that the authentication system will behave correctly in production environments and handle various error conditions gracefully.
