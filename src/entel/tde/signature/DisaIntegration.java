package entel.tde.signature;

import com.google.gson.JsonObject;

import com.siebel.wsserver.operator.CSSWSSingletonOperator;

public class DisaIntegration extends CSSWSSingletonOperator {
    public static final String COMMAND = "Command";

    private static final String PLUGIN_TYPE = "plugin_token_subtel";
    private static final String PLUGIN_VERSION = "1.0.0";

    // Logger.getLogger("disa.server"); //returns DISA system log instance
    // Logs by logger will go into DISA log file
    // java.util.logging.Logger logger = java.util.logging.Logger.getLogger("disa.server");
    // logger.info("Log debug information");

    /*
     * Return the type of this plugin operator.
     */
    @Override
    public String getType() {
        return PLUGIN_TYPE;
    }

    /*
     * Returns the version of this plugin operator
     */
    @Override
    public String getVersion() {
        return PLUGIN_VERSION;
    }

    /*
     * The main logic to process the message DISA gets from Siebel Open UI
     * Any message DISA gets for this component type will be put in a queue,
     * and this method will process messages in this queue.
     *
     * @param msg the current message in message queue
     */
    @Override
    protected void processMessage(JsonObject msg) {
        if (msg.has(COMMAND)) {
            if (msg.get(COMMAND).getAsString().equals("GetSysInfo")) {
                AdvanceSignature advanceSignature = new AdvanceSignature();
                JsonObject hostInfo = advanceSignature.SiebelSign(msg);
                sendMessage(hostInfo);
            }
        }
    }
}
