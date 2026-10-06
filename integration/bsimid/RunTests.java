import java.io.PrintWriter;
import org.junit.platform.engine.discovery.DiscoverySelectors;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.junit.platform.launcher.listeners.SummaryGeneratingListener;

/** Standalone JUnit Platform entry point; no Gradle consumer workspace writes. */
public class RunTests {
    public static void main(String[] args) {
        SummaryGeneratingListener listener = new SummaryGeneratingListener();
        org.junit.platform.launcher.Launcher launcher = LauncherFactory.create();
        launcher.registerTestExecutionListeners(listener);
        launcher.execute(LauncherDiscoveryRequestBuilder.request().selectors(
            DiscoverySelectors.selectClass("ru.mts.bsimid.simulator.BSimAuthLogicalChannelTest")).build());
        listener.getSummary().printTo(new PrintWriter(System.out, true));
        listener.getSummary().printFailuresTo(new PrintWriter(System.out, true));
        if (listener.getSummary().getTestsFoundCount() != 3
                || listener.getSummary().getTestsSucceededCount() != 3) System.exit(1);
    }
}
