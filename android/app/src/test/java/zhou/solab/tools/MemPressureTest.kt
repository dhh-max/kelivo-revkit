package zhou.solab.tools

import org.junit.Assert.assertEquals
import org.junit.Test

class MemPressureTest {

    @Test
    fun peakUsesExecutionLowWaterMarkInsteadOfEndResidency() {
        val peak = MemPressure.ToolMemoryPeak(
            beforeFreeHeapMb = 400,
            afterFreeHeapMb = 390,
            lowestFreeHeapMb = 180,
            beforeNativeMb = 50,
            afterNativeMb = 54,
            peakNativeMb = 130,
            beforePssMb = 300,
            afterPssMb = 310,
            peakPssMb = 520,
            samples = 4,
            costMs = 125,
        )

        assertEquals(10, peak.endHeapDeltaMb)
        assertEquals(220, peak.peakHeapDeltaMb)
        assertEquals(4, peak.endNativeDeltaMb)
        assertEquals(80, peak.peakNativeDeltaMb)
        assertEquals(220, peak.peakPssDeltaMb)
        assertEquals(220L, peak.toMap()["peakPssDeltaMb"])
    }
}
