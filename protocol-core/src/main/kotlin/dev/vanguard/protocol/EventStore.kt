package dev.vanguard.protocol

interface EventStore {
    /** Returns false if the event ID already exists. Call only after successful verification. */
    fun insertIfAbsent(event: EventEnvelope): Boolean
    fun get(eventId: String): EventEnvelope?
    fun all(): List<EventEnvelope>
}

class InMemoryEventStore : EventStore {
    private val events = linkedMapOf<String, EventEnvelope>()

    @Synchronized
    override fun insertIfAbsent(event: EventEnvelope): Boolean {
        if (events.containsKey(event.id)) return false
        events[event.id] = event
        return true
    }

    @Synchronized
    override fun get(eventId: String): EventEnvelope? = events[eventId]

    @Synchronized
    override fun all(): List<EventEnvelope> = events.values.toList()
}

interface RelayQueue {
    fun enqueue(eventId: String): Boolean
    fun nextBatch(limit: Int): List<String>
    fun acknowledge(eventId: String)
}

class InMemoryRelayQueue : RelayQueue {
    private val pending = linkedSetOf<String>()

    @Synchronized
    override fun enqueue(eventId: String): Boolean = pending.add(eventId)

    @Synchronized
    override fun nextBatch(limit: Int): List<String> {
        require(limit > 0)
        return pending.take(limit)
    }

    @Synchronized
    override fun acknowledge(eventId: String) {
        pending.remove(eventId)
    }
}
