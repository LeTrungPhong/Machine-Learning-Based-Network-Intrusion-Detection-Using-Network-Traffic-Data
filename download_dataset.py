from huggingface_hub import hf_hub_download

local_path = hf_hub_download(
    repo_id="bencorn/CICIDS2017",
    repo_type="dataset",
    filename="pcaps/Friday-WorkingHours.pcap",
    local_dir="./dataset"
)

print("Download thành công!")
print("File được lưu tại:", local_path)