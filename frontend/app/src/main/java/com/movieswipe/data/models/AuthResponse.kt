package com.movieswipe.data.models

import com.google.gson.annotations.SerializedName

data class AuthResponse(
    @SerializedName("user")
    val user: User,
    @SerializedName("token")
    val token: String
)

data class ApiResponse<T>(
    @SerializedName("success")
    val success: Boolean,
    @SerializedName("data")
    val data: T? = null,
    @SerializedName("error")
    val error: String? = null,
    @SerializedName("message")
    val message: String? = null
)

data class SignInRequest(
    @SerializedName("token")
    val token: String
)

data class SignOutResponse(
    @SerializedName("message")
    val message: String
)
