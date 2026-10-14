package trust

// The external tests drive one pass of the enrollment and rotation loops at a
// time.
var (
	EnrollPass   = EnrollmentConfig.enrollPass
	SweepOnce    = EnrollmentConfig.sweepOnce
	SweepChains  = EnrollmentConfig.sweepChains
	RotationPass = RotationConfig.rotationPass
)
