package com.movieswipe.data.local

import android.content.SharedPreferences
import com.movieswipe.utils.Constants
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class TokenManager @Inject constructor(
    private val sharedPreferences: SharedPreferences
) {
    
    fun saveAuthToken(token: String) {
        sharedPreferences.edit().putString(Constants.KEY_AUTH_TOKEN, token).apply()
    }
    
    fun getAuthToken(): String? {
        return sharedPreferences.getString(Constants.KEY_AUTH_TOKEN, null)
    }
    
    fun saveUserId(userId: String) {
        sharedPreferences.edit().putString(Constants.KEY_USER_ID, userId).apply()
    }
    
    fun getUserId(): String? {
        return sharedPreferences.getString(Constants.KEY_USER_ID, null)
    }
    
    fun saveUserEmail(email: String) {
        sharedPreferences.edit().putString(Constants.KEY_USER_EMAIL, email).apply()
    }
    
    fun getUserEmail(): String? {
        return sharedPreferences.getString(Constants.KEY_USER_EMAIL, null)
    }
    
    fun clearTokens() {
        sharedPreferences.edit()
            .remove(Constants.KEY_AUTH_TOKEN)
            .remove(Constants.KEY_USER_ID)
            .remove(Constants.KEY_USER_EMAIL)
            .apply()
    }
    
    fun isLoggedIn(): Boolean {
        return getAuthToken() != null
    }
}
