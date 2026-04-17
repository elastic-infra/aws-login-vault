package login

import "testing"

func TestPartitionForRegion(t *testing.T) {
	tests := []struct {
		region string
		want   string
	}{
		{"us-east-1", "aws"},
		{"us-west-2", "aws"},
		{"eu-west-1", "aws"},
		{"ap-northeast-1", "aws"},
		{"cn-north-1", "aws-cn"},
		{"cn-northwest-1", "aws-cn"},
		{"us-gov-west-1", "aws-us-gov"},
		{"us-gov-east-1", "aws-us-gov"},
	}
	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			if got := partitionForRegion(tt.region); got != tt.want {
				t.Errorf("partitionForRegion(%q) = %q, want %q", tt.region, got, tt.want)
			}
		})
	}
}

func TestSigninBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		region  string
		want    string
		wantErr bool
	}{
		{"commercial us-east-1", "us-east-1", "https://us-east-1.signin.aws.amazon.com", false},
		{"commercial ap-northeast-1", "ap-northeast-1", "https://ap-northeast-1.signin.aws.amazon.com", false},
		{"china cn-north-1", "cn-north-1", "https://cn-north-1.signin.amazonaws.cn", false},
		{"govcloud us-gov-west-1", "us-gov-west-1", "https://us-gov-west-1.signin.amazonaws-us-gov.com", false},
		{"empty region rejected", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SigninBaseURL(tt.region)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
