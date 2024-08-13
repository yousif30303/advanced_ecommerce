@extends('admin.admin_master')

@section('admin')
<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>

<div class="mt-4">
    <div class="container">
        <div class="row">
            <div class="col-lg-8 mx-auto">
                <div class="card"><br><br>
                    <h5 class="card-title ml-4">Home Slide Page </h5>

                    <form method="post" action="{{route('update.slider')}}" enctype="multipart/form-data">
                        @csrf
                        <input type="hidden" name="id" value="{{ $homeslide->id }}">
                        <div class="card-body">
                            <div class="row mb-3">
                                <label for="example-text-input" class="col-sm-2 col-form-label">Title</label>
                                <div class="col-sm-10">
                                    <input name="title" class="form-control" type="text" value="{{ $homeslide->title }}"  id="example-text-input">
                                </div>
                            </div>
                            <div class="row mb-3">
                                <label for="example-text-input" class="col-sm-2 col-form-label">Short Title </label>
                                <div class="col-sm-10">
                                    <input name="short_title" class="form-control" type="text" value="{{ $homeslide->short_title }}"  id="example-text-input">
                                </div>
                            </div>
                            <div class="row mb-3">
                                <label for="example-text-input" class="col-sm-2 col-form-label">Video URL </label>
                                <div class="col-sm-10">
                                    <input name="video_url" class="form-control" type="text" value="{{ $homeslide->video_url }}"  id="example-text-input">
                                </div>
                            </div>
                
                            <div class="row mb-3">
                                <label for="example-text-input" class="col-sm-2 col-form-label">Slider Image </label>
                                <div class="col-sm-10">
                                    <input name="home_slide" class="form-control" type="file"  id="image">
                                </div>
                            </div>
                
                            <div class="row mb-3">
                                 <label for="example-text-input" class="col-sm-2 col-form-label">  </label>
                                <div class="col-sm-10">
                                    <img id="showImage" class="rounded avatar-lg" src="{{ (!empty($homeslide->home_slide))? url( $homeslide->home_slide):url('upload/no_image.jpg') }}" alt="Card image cap">                                </div>
                            </div>
                        </div>
                        <button class="btn btn-info btn-rounded waves-effect waves-light ml-4 mb-4" type="submit">Update Slide</button>
                    </form>
                </div>
            </div> 
        </div>
        <div>
            
        </div>
    </div>
</div> 

<script type="text/javascript">
    
    $(document).ready(function(){
        $('#image').change(function(e){
            var reader = new FileReader();
            reader.onload = function(e){
                $('#showImage').attr('src',e.target.result);
            }
            reader.readAsDataURL(e.target.files['0']);
        });
    });
</script>

@endsection