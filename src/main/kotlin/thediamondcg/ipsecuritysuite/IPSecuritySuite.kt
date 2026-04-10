package thediamondcg.ipsecuritysuite

import com.mojang.brigadier.arguments.BoolArgumentType
import com.mojang.brigadier.arguments.StringArgumentType
import com.mojang.brigadier.context.CommandContext
import kotlinx.serialization.json.*
import net.fabricmc.api.ModInitializer
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents
import net.minecraft.commands.CommandSourceStack
import net.minecraft.commands.Commands.*
import net.minecraft.commands.arguments.GameProfileArgument
import net.minecraft.network.chat.Component
import net.minecraft.server.MinecraftServer
import net.minecraft.server.network.ServerGamePacketListenerImpl
import okhttp3.Request
import okhttp3.Response
import java.net.InetSocketAddress

val MOD_ID: String = "ip-security-suite"

class IPSecuritySuite : ModInitializer {
    var ipData: IPDataManager = IPDataManager()

    override fun onInitialize() {
        var root = literal("ipss")

        var locking = literal("lock")
        locking = locking.requires(this::hasSelfLock).executes(this::selfLock)
        locking = locking.then(literal("last").then(argument("player_name", GameProfileArgument.gameProfile()).requires(this::hasOp).executes(this::authLastIp)))
        locking = locking.then(literal("other").then(argument("player_name", GameProfileArgument.gameProfile()).requires(this::hasOp).executes(this::ipLock)))
        locking = locking.then(literal("erase").then(argument("player_name", GameProfileArgument.gameProfile()).requires(this::hasOp).executes(this::eraseIps)))

        var vpn = literal("vpn").requires(this::hasOp)
        vpn = vpn.then(literal("api").then(
            argument("api_key", StringArgumentType.string()).executes(this::setApiKey)
        ))

        var config = literal("config").requires(this::hasOp)
        var config_set = literal("set")
        var config_get = literal("get")

        config_get = config_get.then(literal("strict").executes(this::getStrictMode))
        config_get = config_get.then(literal("vpn").executes(this::getVpnMode))
        config_get = config_get.then(literal("self-lock").executes(this::getSelfLockMode))
        config_get = config_get.then(literal("ip-reveal").executes(this::getIpReveal))

        config_set = config_set.then(literal("strict").then(
            argument("value", BoolArgumentType.bool()).executes(this::strictMode)
        ))
        config_set = config_set.then(literal("vpn").then(
            argument("value", BoolArgumentType.bool()).executes(this::setVpn)
        ))
        config_set = config_set.then(literal("self-lock").then(
            argument("value", BoolArgumentType.bool()).executes(this::selfLockMode)
        ))
        config_set = config_set.then(literal("ip-reveal").requires(this::hasOwner).then(
            argument("value", BoolArgumentType.bool()).executes(this::setIpReveal)
        ))

        config = config.then(config_set)
        config = config.then(config_get)

        root = root.then(config)
        root = root.then(vpn)
        root = root.then(locking)
        root = root.executes(this::tutorialMessage)

        CommandRegistrationCallback.EVENT.register { commandDispatcher, _, registrationEnvironment ->
            if (registrationEnvironment.includeDedicated) {
                commandDispatcher.register(root)
            }
        }

        ServerPlayConnectionEvents.INIT.register { serverPlayNetworkHandler: ServerGamePacketListenerImpl,
                                                   minecraftServer: MinecraftServer ->
            try {
                val player = serverPlayNetworkHandler.player

                val rawAddress = serverPlayNetworkHandler.connection.remoteAddress
                val playerIp = (rawAddress as? InetSocketAddress)?.address?.hostAddress
                    ?: rawAddress?.toString()
                    ?: "unknown"

                ipData.ipData.lastIp[player.uuid.toString()] = playerIp

                val validIp = ipData.validate(player.uuid, playerIp)
                val vpnApiKey = ipData.getApiKey()

                println("IPSS: Login IP $playerIp is " + if (ipData.strictlyValidIp(player.uuid, playerIp)) "approved for logon" else "unregistered")
                if (ipData.ipData.vpnAllowed == false) {
                    println("IPSS: VPN logins are disabled.")
                    println(if (vpnApiKey != null) "IPSS: VPN API key is set!" else "IPSS: VPN API key is unset! VPN FILTERING WILL NOT WORK!")
                } else {
                    println("IPSS: VPNs are allowed to log in.")
                }

                if (!validIp) {
                    serverPlayNetworkHandler.disconnect(Component.literal("Someone tried logging into account ${player.name.string} with unauthorized IP: $playerIp"))
                    minecraftServer.sendSystemMessage(Component.literal("Someone unauthorized tried to login to ${player.name.string}'s account!"))
                }

                if ((ipData.ipData.vpnAllowed == false) && !ipData.strictlyValidIp(player.uuid, playerIp) && (vpnApiKey != null)) {
                    val client = okhttp3.OkHttpClient()

                    val response: Response = client.newCall(
                        Request.Builder().get().url("https://vpnapi.io/api/$playerIp?key=$vpnApiKey").build()
                    ).execute()

                    if (response.body != null) {
                        val body: String = response.body!!.string()
                        val data = Json.parseToJsonElement(body)
                        val isVpn: Boolean = data.jsonObject["security"]?.jsonObject?.containsValue(Json.parseToJsonElement("true")) == true

                        if (isVpn) {
                            serverPlayNetworkHandler.disconnect(Component.literal("VPNs are not allowed."))
                        }
                    }
                }

                ipData.saveData()
            } catch (e: RuntimeException) {
                println("For some reason, authentication failed!?")
                e.printStackTrace()
            }
        }
    }

    private fun tutorialMessage(ctx: CommandContext<CommandSourceStack>): Int {
        ctx.source.sendSuccess({ Component.literal("IP Security Suite -- https://github.com/T-O-R-U-S/ipss") }, false)
        return 1
    }

    private fun ipLock(ctx: CommandContext<CommandSourceStack>): Int {
        val selectedProfiles = GameProfileArgument.getGameProfiles(ctx, "player_name")

        for (playerProfile in selectedProfiles) {
            val playerUuid = playerProfile.id
            val serverPlayer = ctx.source.server.playerList.getPlayer(playerUuid)
            val rawAddress = serverPlayer?.connection?.connection?.remoteAddress
            val playerIp = (rawAddress as? InetSocketAddress)?.address?.hostAddress

            if (playerIp != null) {
                ipData.lockIp(playerUuid, playerIp)
                ipData.saveData()
                ctx.source.sendSuccess({
                    Component.literal("Player with username '${playerProfile.name}' and UUID '$playerUuid' has had their IP locked to ${displayIp(playerIp)}")
                }, true)
            } else {
                ctx.source.sendSuccess({
                    Component.literal("Player with username '${playerProfile.name}' and UUID '$playerUuid' did not get their IP locked because they are offline. Use `/ipss lock last <username>` instead!")
                }, true)
            }
        }

        return 1
    }

    private fun eraseIps(ctx: CommandContext<CommandSourceStack>): Int {
        val selectedProfiles = GameProfileArgument.getGameProfiles(ctx, "player_name")

        for (playerProfile in selectedProfiles) {
            val playerUuid = playerProfile.id

            if (ipData.eraseIPs(playerUuid)) {
                ctx.source.sendSuccess({
                    Component.literal("Player with username '${playerProfile.name}' and UUID '$playerUuid' has had their past IPs erased.")
                }, true)
                ipData.saveData()
            }
        }

        return 1
    }

    private fun selfLock(ctx: CommandContext<CommandSourceStack>): Int {
        val player = ctx.source.player ?: return 2
        val playerUuid = player.uuid
        val rawAddress = player.connection.connection.remoteAddress
        val playerIp = (rawAddress as? InetSocketAddress)?.address?.hostAddress ?: return 2

        ipData.lockIp(playerUuid, playerIp)
        ipData.saveData()

        ctx.source.sendSuccess({
            Component.literal("Locked account with username '${player.name.string}' and UUID '$playerUuid' to its current IP.")
        }, true)

        return 1
    }

    private fun authLastIp(ctx: CommandContext<CommandSourceStack>): Int {
        val playerProfile = GameProfileArgument.getGameProfiles(ctx, "player_name").first()
        val playerUuid = playerProfile.id
        val lastPlayerIp = ipData.getLast(playerUuid)

        if (lastPlayerIp != null) {
            ipData.lockIp(playerUuid, lastPlayerIp)
            ctx.source.sendSuccess({
                Component.literal("Player with username '${playerProfile.name}' and UUID '$playerUuid' has had their IP locked to their last logon IP, which was ${displayIp(lastPlayerIp)}")
            }, true)
            ipData.saveData()
        } else {
            ctx.source.sendSuccess({
                Component.literal("Player with username '${playerProfile.name}' and UUID '$playerUuid' did not get their last IP locked because there is no record of them ever logging on.")
            }, true)
        }

        return 1
    }

    private fun strictMode(ctx: CommandContext<CommandSourceStack>): Int {
        val strictModeSetting = BoolArgumentType.getBool(ctx, "value")

        if (strictModeSetting) {
            ipData.enableStrict()
            ctx.source.sendSuccess({
                Component.literal("Strict mode is enabled. This means any accounts without a pre-existing IP lock cannot join!")
            }, true)
        } else {
            ipData.disableStrict()
            ctx.source.sendSuccess({
                Component.literal("Strict mode is disabled. This means non-IP-locked accounts can join from any IP!")
            }, true)
        }

        ipData.saveData()
        return 1
    }

    private fun getStrictMode(ctx: CommandContext<CommandSourceStack>): Int {
        if (ipData.ipData.strictMode == true) {
            ctx.source.sendSuccess({
                Component.literal("Strict mode is enabled. This means any accounts without a pre-existing IP lock cannot join!")
            }, false)
        } else {
            ipData.disableStrict()
            ctx.source.sendSuccess({
                Component.literal("Strict mode is disabled. This means non-IP-locked accounts can join from any IP!")
            }, false)
        }
        return 1
    }

    private fun selfLockMode(ctx: CommandContext<CommandSourceStack>): Int {
        val selfLockSetting = BoolArgumentType.getBool(ctx, "value")

        ipData.setSelfLocking(selfLockSetting)

        if (selfLockSetting) {
            ctx.source.sendSuccess({
                Component.literal("Self-locking is enabled. This means players can register their own IPs when they first log on. Works best when strict mode is set to false.")
            }, true)
        } else {
            ctx.source.sendSuccess({
                Component.literal("Self-locking is disabled. This means operators have to register players' IPs when they log on.")
            }, true)
        }

        ipData.saveData()
        return 1
    }

    private fun getSelfLockMode(ctx: CommandContext<CommandSourceStack>): Int {
        if (ipData.ipData.canLockForSelf != false) {
            ctx.source.sendSuccess({
                Component.literal("Self-locking is enabled. This means players can register their own IPs when they first log on. Works best when strict mode is set to false.")
            }, false)
        } else {
            ctx.source.sendSuccess({
                Component.literal("Self-locking is disabled. This means operators have to register players' IPs when they log on.")
            }, false)
        }
        return 1
    }

    private fun setVpn(ctx: CommandContext<CommandSourceStack>): Int {
        val vpnSetting = BoolArgumentType.getBool(ctx, "value")

        ipData.setVpnAllowed(vpnSetting)

        if (vpnSetting) {
            ctx.source.sendSuccess({ Component.literal("VPN logins are now enabled.") }, true)
        } else {
            if (ipData.getApiKey() == null) {
                ctx.source.sendSuccess({
                    Component.literal("You don't seem to have a vpnapi.io API key setup. This means that this option will not work. Set an api key with /ipss vpn api <YOURKEYHERE>")
                }, false)
            }
            ctx.source.sendSuccess({
                Component.literal("VPN logins are no longer enabled. Note that if you run out of API requests, all IPs are allowed to connect.")
            }, true)
        }

        ipData.saveData()
        return 1
    }

    private fun setIpReveal(ctx: CommandContext<CommandSourceStack>): Int {
        val ipRevealSetting = BoolArgumentType.getBool(ctx, "value")

        ipData.ipData.revealIp = ipRevealSetting

        if (ipRevealSetting) {
            ctx.source.sendSuccess({
                Component.literal("Now, whenever an admin locks someone's IP, the newly-locked IP will also be revealed to server operators. Welcome to the danger-dome!")
            }, true)
        } else {
            ctx.source.sendSuccess({
                Component.literal("IPs are hidden when an admin locks someone's IP.")
            }, true)
        }

        ipData.saveData()
        return 1
    }

    private fun getIpReveal(ctx: CommandContext<CommandSourceStack>): Int {
        if (ipData.ipData.revealIp == true) {
            ctx.source.sendSuccess({
                Component.literal("Whenever an admin locks someone's IP, the newly-locked IP will also be revealed to server operators. Welcome to the danger-dome!")
            }, false)
        } else {
            ctx.source.sendSuccess({
                Component.literal("IPs are hidden when an admin locks someone's IP.")
            }, false)
        }
        return 1
    }

    private fun displayIp(ip: String): String {
        return if (ipData.ipData.revealIp == true) ip else "their last IP"
    }

    private fun getVpnMode(ctx: CommandContext<CommandSourceStack>): Int {
        if (ipData.ipData.vpnAllowed == false) {
            ctx.source.sendSuccess({
                Component.literal("VPN logins are not enabled. Note that if you run out of API requests, all IPs are allowed to connect.")
            }, false)
        } else {
            ctx.source.sendSuccess({ Component.literal("VPN logins are enabled.") }, false)
        }
        return 1
    }

    private fun setApiKey(ctx: CommandContext<CommandSourceStack>): Int {
        val perpetrator = ctx.source.player?.name?.string ?: "the server terminal"
        val apiKey = StringArgumentType.getString(ctx, "api_key")

        ipData.setApiKey(apiKey)

        ctx.source.sendSuccess({
            Component.literal("The VPN API key has been updated by $perpetrator.")
        }, true)

        ipData.saveData()
        return 1
    }

    // Permission level 3 = admin (can use /ban, /deop, /kick, /op)
    private fun hasOp(src: CommandSourceStack): Boolean {
        return LEVEL_ADMINS.check(src.permissions())
    }

    // Permission level 4 = owner (can use /stop)
    private fun hasOwner(src: CommandSourceStack): Boolean {
        return LEVEL_OWNERS.check(src.permissions())
    }

    private fun hasSelfLock(src: CommandSourceStack): Boolean {
        return ((ipData.ipData.canLockForSelf ?: true) || this.hasOp(src))
    }
}