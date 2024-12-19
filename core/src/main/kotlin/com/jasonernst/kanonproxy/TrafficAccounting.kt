package com.jasonernst.kanonproxy

interface TrafficAccounting {
    fun recordToInternet(bytes: Long)

    fun recordFromInternet(bytes: Long)
}
