package com.jasonernst.kanonproxy

object DummyTrafficAccount : TrafficAccounting {
    override fun recordToInternet(bytes: Long) {
        // do nothing
    }

    override fun recordFromInternet(bytes: Long) {
        // do nothing
    }
}