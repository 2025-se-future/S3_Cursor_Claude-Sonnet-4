package com.movieswipe.ui.viewmodels.users

import androidx.compose.runtime.State
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.tasks.Task
import com.movieswipe.data.models.AuthResponse
import com.movieswipe.data.models.User
import com.movieswipe.data.repositories.users.AuthRepository
import com.movieswipe.utils.Constants
import com.movieswipe.utils.UiState
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AuthViewModel @Inject constructor(
    private val authRepository: AuthRepository
) : ViewModel() {
    
    private val _signInState = mutableStateOf<UiState<AuthResponse>>(UiState.Idle)
    val signInState: State<UiState<AuthResponse>> = _signInState
    
    private val _signOutState = mutableStateOf<UiState<String>>(UiState.Idle)
    val signOutState: State<UiState<String>> = _signOutState
    
    private val _userState = mutableStateOf<UiState<User>>(UiState.Idle)
    val userState: State<UiState<User>> = _userState
    
    private val _isLoggedIn = mutableStateOf(false)
    val isLoggedIn: State<Boolean> = _isLoggedIn
    
    init {
        checkAuthStatus()
    }
    
    fun getGoogleSignInClient(): GoogleSignInClient {
        return authRepository.getGoogleSignInClient()
    }
    
    fun handleGoogleSignInResult(task: Task<GoogleSignInAccount>) {
        viewModelScope.launch {
            _signInState.value = UiState.Loading
            
            val result = authRepository.handleGoogleSignInResult(task)
            
            if (result.isSuccess) {
                _signInState.value = UiState.Success(result.getOrNull()!!)
                _isLoggedIn.value = true
                getCurrentUser() // Load user profile after successful sign in
            } else {
                val error = result.exceptionOrNull()
                _signInState.value = UiState.Error(
                    error?.message ?: Constants.ERROR_AUTHENTICATION,
                    error
                )
                _isLoggedIn.value = false
            }
        }
    }
    
    fun signOut() {
        viewModelScope.launch {
            _signOutState.value = UiState.Loading
            
            val result = authRepository.signOut()
            
            if (result.isSuccess) {
                _signOutState.value = UiState.Success(result.getOrNull()!!)
                _isLoggedIn.value = false
                _userState.value = UiState.Idle
                resetSignInState()
            } else {
                val error = result.exceptionOrNull()
                _signOutState.value = UiState.Error(
                    error?.message ?: "Sign out failed",
                    error
                )
                // Even if sign out fails on backend, user is logged out locally
                _isLoggedIn.value = false
                _userState.value = UiState.Idle
            }
        }
    }
    
    fun getCurrentUser() {
        viewModelScope.launch {
            _userState.value = UiState.Loading
            
            val result = authRepository.getCurrentUser()
            
            if (result.isSuccess) {
                _userState.value = UiState.Success(result.getOrNull()!!)
            } else {
                val error = result.exceptionOrNull()
                _userState.value = UiState.Error(
                    error?.message ?: "Failed to load user profile",
                    error
                )
            }
        }
    }
    
    fun checkAuthStatus() {
        _isLoggedIn.value = authRepository.isLoggedIn()
        if (_isLoggedIn.value) {
            getCurrentUser()
        }
    }
    
    fun resetSignInState() {
        _signInState.value = UiState.Idle
    }
    
    fun resetSignOutState() {
        _signOutState.value = UiState.Idle
    }
    
    fun resetUserState() {
        _userState.value = UiState.Idle
    }
}
