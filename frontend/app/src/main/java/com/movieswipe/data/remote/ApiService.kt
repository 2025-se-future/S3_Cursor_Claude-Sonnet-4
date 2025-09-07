package com.movieswipe.data.remote

import com.movieswipe.data.models.ApiResponse
import com.movieswipe.data.models.AuthResponse
import com.movieswipe.data.models.SignInRequest
import com.movieswipe.data.models.SignOutResponse
import com.movieswipe.data.models.User
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Header
import retrofit2.http.POST
import retrofit2.http.Path

interface ApiService {
    
    @POST("api/users/auth/signin")
    suspend fun signIn(@Body request: SignInRequest): Response<ApiResponse<AuthResponse>>
    
    @POST("api/users/auth/signout")
    suspend fun signOut(@Header("Authorization") authorization: String): Response<ApiResponse<SignOutResponse>>
    
    @GET("api/users/me")
    suspend fun getCurrentUser(@Header("Authorization") authorization: String): Response<ApiResponse<User>>
    
    @GET("api/users/{userId}")
    suspend fun getUserById(
        @Path("userId") userId: String,
        @Header("Authorization") authorization: String
    ): Response<ApiResponse<User>>
}
