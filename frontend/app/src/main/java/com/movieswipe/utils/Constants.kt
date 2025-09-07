package com.movieswipe.utils

object Constants {
    // API
    const val BASE_URL = "http://10.0.2.2:3000/" // Android emulator localhost
    const val BASE_URL_REAL_DEVICE = "http://192.168.1.100:3000/" // Change to your actual IP
    
    // SharedPreferences
    const val PREFS_NAME = "movieswipe_prefs"
    const val KEY_AUTH_TOKEN = "auth_token"
    const val KEY_USER_ID = "user_id"
    const val KEY_USER_EMAIL = "user_email"
    
    // Google OAuth
    const val GOOGLE_SIGN_IN_REQUEST_CODE = 100
    
    // Timeouts
    const val NETWORK_TIMEOUT = 30L
    
    // Error Messages
    const val ERROR_NETWORK = "Network error. Please check your connection."
    const val ERROR_AUTHENTICATION = "Authentication failed. Please try again."
    const val ERROR_UNKNOWN = "An unexpected error occurred."
}
