package dev.vanguard.nearby

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Base64
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsClient
import com.google.android.gms.nearby.connection.ConnectionsStatusCodes
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import kotlinx.coroutines.tasks.await
import java.util.concurrent.ConcurrentHashMap

class VanguardNearbyModule : Module() {
  private var client: ConnectionsClient? = null
  private var localEndpointName = "Vanguard device"
  private var advertising = false
  private var discovering = false
  private val connectedEndpoints = ConcurrentHashMap.newKeySet<String>()
  private val discoveredEndpoints = ConcurrentHashMap<String, String>()
  private val pendingEndpoints = ConcurrentHashMap.newKeySet<String>()

  private val payloadCallback = object : PayloadCallback() {
    override fun onPayloadReceived(endpointId: String, payload: Payload) {
      if (payload.type != Payload.Type.BYTES) {
        client?.cancelPayload(payload.id)
        sendEvent("onTransportError", mapOf(
          "code" to "unsupported_payload_type",
          "endpointId" to endpointId
        ))
        return
      }

      val bytes = payload.asBytes() ?: return
      if (bytes.size > MAX_PACKET_BYTES) {
        sendEvent("onTransportError", mapOf(
          "code" to "payload_too_large",
          "endpointId" to endpointId
        ))
        client?.disconnectFromEndpoint(endpointId)
        return
      }

      sendEvent("onPayloadReceived", mapOf(
        "endpointId" to endpointId,
        "payloadBase64Url" to encodeUrl(bytes),
        "byteLength" to bytes.size
      ))
    }

    override fun onPayloadTransferUpdate(
      endpointId: String,
      update: PayloadTransferUpdate
    ) {
      val status = when (update.status) {
        PayloadTransferUpdate.Status.SUCCESS -> "success"
        PayloadTransferUpdate.Status.FAILURE -> "failure"
        PayloadTransferUpdate.Status.CANCELED -> "canceled"
        PayloadTransferUpdate.Status.IN_PROGRESS -> "in_progress"
        else -> "unknown"
      }
      sendEvent("onPayloadTransferUpdate", mapOf(
        "endpointId" to endpointId,
        "payloadId" to update.payloadId,
        "status" to status,
        "bytesTransferred" to update.bytesTransferred,
        "totalBytes" to update.totalBytes
      ))
    }
  }

  private val lifecycleCallback = object : ConnectionLifecycleCallback() {
    override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
      pendingEndpoints.add(endpointId)
      sendEvent("onConnectionInitiated", mapOf(
        "endpointId" to endpointId,
        "endpointName" to info.endpointName,
        "authenticationDigits" to info.authenticationDigits,
        "isIncomingConnection" to info.isIncomingConnection
      ))
    }

    override fun onConnectionResult(endpointId: String, resolution: ConnectionResolution) {
      pendingEndpoints.remove(endpointId)
      val connected = resolution.status.statusCode == ConnectionsStatusCodes.STATUS_OK
      if (connected) {
        connectedEndpoints.add(endpointId)
      } else {
        connectedEndpoints.remove(endpointId)
      }
      sendEvent("onConnectionStateChanged", mapOf(
        "endpointId" to endpointId,
        "state" to if (connected) "connected" else "rejected",
        "statusCode" to resolution.status.statusCode
      ))
    }

    override fun onDisconnected(endpointId: String) {
      connectedEndpoints.remove(endpointId)
      pendingEndpoints.remove(endpointId)
      sendEvent("onConnectionStateChanged", mapOf(
        "endpointId" to endpointId,
        "state" to "disconnected"
      ))
    }
  }

  private val discoveryCallback = object : EndpointDiscoveryCallback() {
    override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
      discoveredEndpoints[endpointId] = info.endpointName
      sendEvent("onPeerFound", mapOf(
        "endpointId" to endpointId,
        "endpointName" to info.endpointName,
        "serviceId" to info.serviceId
      ))
    }

    override fun onEndpointLost(endpointId: String) {
      discoveredEndpoints.remove(endpointId)
      sendEvent("onPeerLost", mapOf("endpointId" to endpointId))
    }
  }

  override fun definition() = ModuleDefinition {
    Name("VanguardNearby")

    Events(
      "onPeerFound",
      "onPeerLost",
      "onConnectionInitiated",
      "onConnectionStateChanged",
      "onPayloadReceived",
      "onPayloadTransferUpdate",
      "onTransportError",
      "onTransportStateChanged"
    )

    AsyncFunction("getMissingPermissions") {
      val context = requireContext()
      missingPermissions(context)
    }

    AsyncFunction("startAdvertising") { serviceId: String, endpointName: String ->
      validateServiceId(serviceId)
      requireRadioPermissions()
      val nearby = getClient()
      localEndpointName = sanitizeEndpointName(endpointName)
      nearby.startAdvertising(
        localEndpointName,
        serviceId,
        lifecycleCallback,
        AdvertisingOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build()
      ).await()
      advertising = true
      sendEvent("onTransportStateChanged", mapOf("state" to "advertising"))
      null
    }

    AsyncFunction("startDiscovery") { serviceId: String ->
      validateServiceId(serviceId)
      requireRadioPermissions()
      val nearby = getClient()
      nearby.startDiscovery(
        serviceId,
        discoveryCallback,
        DiscoveryOptions.Builder().setStrategy(Strategy.P2P_CLUSTER).build()
      ).await()
      discovering = true
      sendEvent("onTransportStateChanged", mapOf("state" to "discovering"))
      null
    }

    AsyncFunction("requestConnection") { endpointId: String ->
      requireRadioPermissions()
      require(endpointId in discoveredEndpoints) { "Endpoint is not currently discovered" }
      getClient().requestConnection(localEndpointName, endpointId, lifecycleCallback).await()
      null
    }

    AsyncFunction("acceptConnection") { endpointId: String ->
      require(endpointId in pendingEndpoints) { "No pending connection request for this endpoint" }
      getClient().acceptConnection(endpointId, payloadCallback).await()
      null
    }

    AsyncFunction("rejectConnection") { endpointId: String ->
      require(endpointId in pendingEndpoints) { "No pending connection request for this endpoint" }
      getClient().rejectConnection(endpointId).await()
      pendingEndpoints.remove(endpointId)
      null
    }

    AsyncFunction("sendBytes") { endpointId: String, payloadBase64Url: String ->
      require(endpointId in connectedEndpoints) { "Endpoint is not connected" }
      val bytes = decodeUrl(payloadBase64Url)
      require(bytes.isNotEmpty() && bytes.size <= MAX_PACKET_BYTES) {
        "Payload must be between 1 byte and $MAX_PACKET_BYTES bytes"
      }
      getClient().sendPayload(endpointId, Payload.fromBytes(bytes)).await()
      mapOf("queued" to true, "byteLength" to bytes.size)
    }

    AsyncFunction("disconnect") { endpointId: String ->
      getClient().disconnectFromEndpoint(endpointId)
      connectedEndpoints.remove(endpointId)
      pendingEndpoints.remove(endpointId)
      null
    }

    AsyncFunction("stop") {
      val nearby = client
      if (nearby != null) {
        if (advertising) nearby.stopAdvertising()
        if (discovering) nearby.stopDiscovery()
        nearby.stopAllEndpoints()
      }
      advertising = false
      discovering = false
      connectedEndpoints.clear()
      discoveredEndpoints.clear()
      pendingEndpoints.clear()
      sendEvent("onTransportStateChanged", mapOf("state" to "idle"))
      null
    }

    OnDestroy {
      client?.stopAdvertising()
      client?.stopDiscovery()
      client?.stopAllEndpoints()
      client = null
    }
  }

  private fun requireContext(): Context =
    requireNotNull(appContext.reactContext) {
      "Vanguard Nearby requires an active Android application context"
    }.applicationContext

  private fun getClient(): ConnectionsClient {
    if (client == null) client = Nearby.getConnectionsClient(requireContext())
    return requireNotNull(client)
  }

  private fun requireRadioPermissions() {
    val missing = missingPermissions(requireContext())
    check(missing.isEmpty()) {
      "Nearby permissions are missing: ${missing.joinToString(", ")}. Grant them before starting discovery or advertising."
    }
  }

  private fun validateServiceId(value: String) {
    require(value.matches(Regex("^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$"))) {
      "Service ID must be 3-128 characters and contain only letters, numbers, dots, underscores, or hyphens"
    }
  }

  private fun sanitizeEndpointName(value: String): String {
    val cleaned = value.trim().replace(Regex("[^A-Za-z0-9 _.-]"), "")
    require(cleaned.isNotEmpty() && cleaned.length <= 32) {
      "Endpoint name must contain 1-32 supported characters"
    }
    return cleaned
  }

  private fun missingPermissions(context: Context): List<String> {
    val required = buildList {
      if (Build.VERSION.SDK_INT >= 31) {
        add(Manifest.permission.BLUETOOTH_SCAN)
        add(Manifest.permission.BLUETOOTH_CONNECT)
        add(Manifest.permission.BLUETOOTH_ADVERTISE)
      } else if (Build.VERSION.SDK_INT >= 23) {
        add(Manifest.permission.ACCESS_COARSE_LOCATION)
      }

      if (Build.VERSION.SDK_INT in 29..32) {
        add(Manifest.permission.ACCESS_FINE_LOCATION)
      }

      if (Build.VERSION.SDK_INT in 33..36) {
        add(Manifest.permission.NEARBY_WIFI_DEVICES)
      }
      if (Build.VERSION.SDK_INT >= 37) {
        add(Manifest.permission.NEARBY_WIFI_DEVICES)
        add(ACCESS_LOCAL_NETWORK_PERMISSION)
      }
    }

    return required.distinct().filter { permission ->
      context.checkSelfPermission(permission) != PackageManager.PERMISSION_GRANTED
    }
  }

  private fun encodeUrl(bytes: ByteArray): String =
    Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

  private fun decodeUrl(value: String): ByteArray {
    require(value.isNotEmpty() && value.matches(Regex("^[A-Za-z0-9_-]+$"))) {
      "Invalid base64url payload"
    }
    val decoded = Base64.decode(value, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    require(encodeUrl(decoded) == value) { "Non-canonical base64url payload" }
    return decoded
  }

  companion object {
    private const val MAX_PACKET_BYTES = 24 * 1024
    private const val ACCESS_LOCAL_NETWORK_PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
  }
}
