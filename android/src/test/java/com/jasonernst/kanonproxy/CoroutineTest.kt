import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Test
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadFactory
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext


class CoroutineTest {

    @Test
    fun longLatencyForUserOnDefaultDispatcherTest() {
        val runtime = Runtime.getRuntime()
        val usedMemoryBefore = runtime.totalMemory() - runtime.freeMemory()
        runBlocking {
            val coroutineScope = CoroutineScope(EmptyCoroutineContext)
            val startTime = System.currentTimeMillis()
            // use unconfined dispatcher to make sure that all "background"
            // tasks submitted before user action
            val backgroundJob = coroutineScope.launch(Dispatchers.Unconfined) {
                // simulate background processing of images
                repeat(Runtime.getRuntime().availableProcessors() * 100) {
                    launch(Dispatchers.Default) {
                        // simulate algorithm invocation for 100 ms
                        // (fake load just to avoid elimination optimization by compilers)
                        val finishTimeMillis = System.currentTimeMillis() + 100
                        var counter = 0
                        while (System.currentTimeMillis() < finishTimeMillis) {
                            counter++
                        }
                        if (counter > 250000000) {
                            println("wow, your device has really fast cores")
                        }
                    }
                }
            }
            // simulate user action
            val userJob = coroutineScope.launch(Dispatchers.Default) {
                println("user action")
            }
            backgroundJob.invokeOnCompletion {
                println("background processing completed in: ${System.currentTimeMillis() - startTime} ms")
            }
            userJob.invokeOnCompletion {
                println("user action latency: ${System.currentTimeMillis() - startTime} ms")
            }
            joinAll(backgroundJob, userJob)
        }
        val usedMemoryAfter = runtime.totalMemory() - runtime.freeMemory()
        println("Memory increased: " + (usedMemoryAfter - usedMemoryBefore))
    }

    @Test
    fun badLongLatencyForUserOnDefaultDispatcherTest() {
        val runtime = Runtime.getRuntime()
        val usedMemoryBefore = runtime.totalMemory() - runtime.freeMemory()
        runBlocking {
            val coroutineScope = CoroutineScope(EmptyCoroutineContext)
            val startTime = System.currentTimeMillis()
            // use unconfined dispatcher to make sure that all "background"
            // tasks submitted before user action
            val backgroundJob = coroutineScope.launch(Dispatchers.Unconfined) {
                // simulate background processing of images
                repeat(Runtime.getRuntime().availableProcessors() * 100) {
                    launch(BackgroundDispatcher) {
                        // simulate algorithm invocation for 100 ms
                        // (fake load just to avoid elimination optimization by compilers)
                        val finishTimeMillis = System.currentTimeMillis() + 100
                        var counter = 0
                        while (System.currentTimeMillis() < finishTimeMillis) {
                            counter++
                        }
                        if (counter > 250000000) {
                            println("wow, your device has really fast cores")
                        }
                    }
                }
            }
            // simulate user action
            val userJob = coroutineScope.launch(BackgroundDispatcher) {
                println("user action")
            }
            backgroundJob.invokeOnCompletion {
                println("background processing completed in: ${System.currentTimeMillis() - startTime} ms")
            }
            userJob.invokeOnCompletion {
                println("user action latency: ${System.currentTimeMillis() - startTime} ms")
            }
            joinAll(backgroundJob, userJob)
        }
        val usedMemoryAfter = runtime.totalMemory() - runtime.freeMemory()
        println("Memory increased: " + (usedMemoryAfter - usedMemoryBefore))
    }

    @Test
    fun fixedLongLatencyForUserOnDefaultDispatcherTest() {
        val runtime = Runtime.getRuntime()
        val usedMemoryBefore = runtime.totalMemory() - runtime.freeMemory()
        runBlocking {
            val coroutineScope = CoroutineScope(EmptyCoroutineContext)
            val startTime = System.currentTimeMillis()
            // use unconfined dispatcher to make sure that all "background"
            // tasks submitted before user action
            val backgroundJob = coroutineScope.launch(Dispatchers.Unconfined) {
                // simulate background processing of images
                repeat(Runtime.getRuntime().availableProcessors() * 100) {
                    launch(Dispatchers.Default) {
                        // simulate algorithm invocation for 100 ms
                        // (fake load just to avoid elimination optimization by compilers)
                        val finishTimeMillis = System.currentTimeMillis() + 100
                        var counter = 0
                        while (System.currentTimeMillis() < finishTimeMillis) {
                            counter++
                            yield()
                        }
                        if (counter > 250000000) {
                            println("wow, your device has really fast cores")
                        }
                    }
                }
            }
            // simulate user action
            val userJob = coroutineScope.launch(Dispatchers.Default) {
                println("user action")
            }
            backgroundJob.invokeOnCompletion {
                println("background processing completed in: ${System.currentTimeMillis() - startTime} ms")
            }
            userJob.invokeOnCompletion {
                println("user action latency: ${System.currentTimeMillis() - startTime} ms")
            }
            joinAll(backgroundJob, userJob)
        }
        val usedMemoryAfter = runtime.totalMemory() - runtime.freeMemory()
        println("Memory increased: " + (usedMemoryAfter - usedMemoryBefore))
    }
}


object BackgroundDispatcher : CoroutineDispatcher() {

    private val threadFactory = object : ThreadFactory {
        private val threadCount = AtomicInteger(0)
        private val nextThreadName get() = "BackgroundDispatcher-worker-${threadCount.incrementAndGet()}"

        override fun newThread(runnable: Runnable): Thread {
            return Thread(runnable, nextThreadName)
        }
    }

    private val threadPool = ThreadPoolExecutor(
        3,
        Integer.MAX_VALUE,
        60L,
        TimeUnit.SECONDS,
        SynchronousQueue<Runnable>(),
        threadFactory
    );

    private val dispatcher = threadPool.asCoroutineDispatcher()

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        dispatcher.dispatch(context, block)
    }

    /**
     * Background CoroutineDispatcher for Android applications which replaces both
     * [Dispatchers.Default] and [Dispatchers.IO].
     */
    val Dispatchers.Background get() = BackgroundDispatcher

}