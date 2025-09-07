package com.movieswipe.data.repositories.users

import android.content.Context
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.ApiException
import com.google.android.gms.tasks.Task
import com.movieswipe.data.local.TokenManager
import com.movieswipe.data.models.ApiResponse
import com.movieswipe.data.models.AuthResponse
import com.movieswipe.data.models.SignInRequest
import com.movieswipe.data.models.SignOutResponse
import com.movieswipe.data.models.User
import com.movieswipe.data.remote.ApiService
import com.movieswipe.utils.Constants
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.tasks.await
import retrofit2.Response
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AuthRepository @Inject constructor(
    @ApplicationContext private val context: Context,
    private val apiService: ApiService,
    private val tokenManager: TokenManager
) {
    
    private val googleSignInClient: GoogleSignInClient by lazy {
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestIdToken("YOUR_GOOGLE_WEB_CLIENT_ID") // This will be provided by user
            .requestEmail()
            .build()
        
        GoogleSignIn.getClient(context, gso)
    }
    
    fun getGoogleSignInClient(): GoogleSignInClient = googleSignInClient
    
    suspend fun signInWithGoogle(idToken: String): Result<AuthResponse> {
        return try {
            val request = SignInRequest(idToken)
            val response = apiService.signIn(request)
            
            if (response.isSuccessful && response.body()?.success == true) {
                val authResponse = response.body()!!.data!!
                
                // Save tokens and user info
                tokenManager.saveAuthToken(authResponse.token)
                tokenManager.saveUserId(authResponse.user.id)
                tokenManager.saveUserEmail(authResponse.user.email)
                
                Result.success(authResponse)
            } else {
                val errorMessage = response.body()?.message ?: "Sign in failed"
                Result.failure(Exception(errorMessage))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    suspend fun signOut(): Result<String> {
        return try {
            val token = tokenManager.getAuthToken()
            if (token != null) {
                val response = apiService.signOut("Bearer $token")
                
                if (response.isSuccessful && response.body()?.success == true) {
                    // Sign out from Google
                    googleSignInClient.signOut().await()
                    
                    // Clear local tokens
                    tokenManager.clearTokens()
                    
                    val message = response.body()?.data?.message ?: "Successfully signed out"
                    Result.success(message)
                } else {
                    // Even if backend fails, clear local tokens
                    tokenManager.clearTokens()
                    googleSignInClient.signOut().await()
                    
                    val errorMessage = response.body()?.message ?: "Sign out failed"
                    Result.success(errorMessage) // Still consider it success for local cleanup
                }
            } else {
                Result.failure(Exception("No auth token found"))
            }
        } catch (e: Exception) {
            // Clear local tokens even if there's an error
            tokenManager.clearTokens()
            try {
                googleSignInClient.signOut().await()
            } catch (googleException: Exception) {
                // Ignore Google sign out errors
            }
            Result.failure(e)
        }
    }
    
    suspend fun getCurrentUser(): Result<User> {
        return try {
            val token = tokenManager.getAuthToken()
            if (token != null) {
                val response = apiService.getCurrentUser("Bearer $token")
                
                if (response.isSuccessful && response.body()?.success == true) {
                    Result.success(response.body()!!.data!!)
                } else {
                    val errorMessage = response.body()?.message ?: "Failed to get user profile"
                    Result.failure(Exception(errorMessage))
                }
            } else {
                Result.failure(Exception("No auth token found"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    fun isLoggedIn(): Boolean = tokenManager.isLoggedIn()
    
    fun getStoredToken(): String? = tokenManager.getAuthToken()
    
    fun getStoredUserId(): String? = tokenManager.getUserId()
    
    suspend fun handleGoogleSignInResult(task: Task<GoogleSignInAccount>): Result<AuthResponse> {
        return try {
            val account = task.getResult(ApiException::class.java)
            val idToken = account.idToken
            
            if (idToken != null) {
                signInWithGoogle(idToken)
            } else {
                Result.failure(Exception("Failed to get ID token from Google"))
            }
        } catch (e: ApiException) {
            Result.failure(Exception("Google sign in failed: ${e.message}"))
        }
    }
}
